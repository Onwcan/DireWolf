//! A workload's egress authorisation, in force (F-17, ADR-0061, Proposed).
//!
//! The environment's grant is the ceiling; the authorisation is the
//! authority's decision for one workload, held only while it is supervised.
//! The broker evaluates no rule: it looks a pinned address up in the typed
//! authorisation and reads a bit (`WorkloadEgress::allows_all`).
//!
//! # One lock per workspace root
//!
//! Every environment whose workspace is the same root shares one [`Root`],
//! and one mutex guards everything a decision reads or changes there: each
//! environment's authorisation, which of its destinations a tunnel has
//! reached, whether the root is exposed, and every open tunnel. A CONNECT is
//! decided under it twice -- before its name is resolved
//! ([`Root::consider`]) and, with its pinned addresses, when it is admitted
//! and registered ([`Root::admit`]) -- and the first byte any origin sends
//! back on any tunnel of the root takes it before that byte is forwarded
//! ([`Root::origin_byte`]):
//!
//! 1. the destination is reached for its workload (its `SEEN` cells apply);
//! 2. if the root was not exposed, it is now: every authorisation on it
//!    switches to its exposed cells, and every open tunnel on it that its
//!    exposed cell -- for the novelty it was decided with -- no longer
//!    allows is shut, both ways (`EXPOSURE_REVOKED`);
//! 3. only then is the byte forwarded.
//!
//! So until the root's first origin byte reaches a workload no workload on
//! the root has received anything from an origin, and every decision made
//! before then is made in the state that was true; from then on every
//! decision, and every tunnel still open, is the exposed one. There is no
//! window between the transition and a decision: both hold the lock.
//!
//! A workload's end ([`Root::finish`]) takes the lock, removes its
//! authorisation, shuts its open tunnels (`WORKLOAD_ENDED`) and returns what
//! they did. A byte that arrives after that finds no authorisation and is
//! never forwarded.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use dwk_proto::brokerp::BrokerRefusal;
use dwk_proto::brokerp::egress::{
    EgressAddress, EgressAddressUse, EgressAddressUses, EgressCount, EgressCountList,
    EgressCountValue, EgressDisposition, MAX_REPORTED_ADDRESSES, WorkloadEgress,
    WorkloadEgressReport, WorkloadEgressTargetReport, WorkloadEgressTargetReports, address_text,
};
use dwk_proto::wire::guard::Address;
use dwk_proto::wire::id::InvocationId;
use dwk_proto::wire::scalar::ByteCount;

/// A workspace root's identity: its device and inode.
pub(crate) type RootKey = (u64, u64);

/// Every workspace root this broker has had an environment on. A root is
/// never forgotten while the broker runs: its exposure only ever rises.
#[derive(Debug, Default)]
pub(crate) struct Roots(Mutex<BTreeMap<RootKey, Arc<Root>>>);

impl Roots {
    /// The root `key`, made on first use.
    pub(crate) fn of(&self, key: RootKey) -> Arc<Root> {
        let mut roots = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        Arc::clone(roots.entry(key).or_default())
    }
}

/// One workspace root's egress state.
#[derive(Debug, Default)]
pub(crate) struct Root {
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    /// Whether any origin byte has reached any workload on the root.
    exposed: bool,
    /// Each environment's workload's authorisation, while it is supervised.
    members: BTreeMap<String, Member>,
    /// The next tunnel's number.
    next: u64,
}

/// A counted disposition.
type Counts = BTreeMap<&'static str, (EgressDisposition, u64)>;

fn count(counts: &mut Counts, disposition: EgressDisposition) {
    let entry = counts
        .entry(disposition.as_str())
        .or_insert((disposition, 0));
    entry.1 = entry.1.saturating_add(1);
}

/// One destination's tallies.
#[derive(Debug, Default)]
struct Tally {
    reached: bool,
    dispositions: Counts,
    /// Distinct addresses judged: allowed, refused.
    addresses: Vec<(Address, u64, u64)>,
    omitted: u64,
    bytes: Arc<Bytes>,
}

impl Tally {
    fn address(&mut self, address: Address, allowed: bool) {
        if let Some(entry) = self.addresses.iter_mut().find(|(a, _, _)| *a == address) {
            if allowed {
                entry.1 = entry.1.saturating_add(1);
            } else {
                entry.2 = entry.2.saturating_add(1);
            }
        } else if self.addresses.len() < MAX_REPORTED_ADDRESSES {
            self.addresses
                .push((address, u64::from(allowed), u64::from(!allowed)));
        } else {
            self.omitted = self.omitted.saturating_add(1);
        }
    }
}

/// Bytes a destination's tunnels carried, each way.
#[derive(Debug, Default)]
pub(crate) struct Bytes {
    up: AtomicU64,
    down: AtomicU64,
}

impl Bytes {
    /// Count `n` bytes carried to the origin.
    pub(crate) fn up(&self, n: u64) {
        self.up.fetch_add(n, Ordering::SeqCst);
    }

    /// Count `n` bytes carried back.
    pub(crate) fn down(&self, n: u64) {
        self.down.fetch_add(n, Ordering::SeqCst);
    }
}

/// An environment's workload's authorisation, in force.
#[derive(Debug)]
struct Member {
    invocation: InvocationId,
    egress: WorkloadEgress,
    /// Per destination: reached, so the `SEEN` cells apply.
    seen: Vec<bool>,
    /// Whether the exposed cells apply.
    exposed: bool,
    /// Whether an origin byte reached this workload.
    reached_origin: bool,
    open: BTreeMap<u64, Open>,
    tallies: Vec<Tally>,
    unattributed: Counts,
}

#[derive(Debug)]
struct Open {
    target: usize,
    /// The novelty it was decided with: a connection's novelty is fixed when
    /// it is decided, as a `net.http` hop's is; only exposure re-decides it.
    seen: bool,
    addresses: Vec<Address>,
    handle: Arc<Handle>,
}

/// A way to shut one of a tunnel's sockets both ways, given by the code
/// that holds the socket (`tunnel.rs`): the root stops a tunnel without
/// holding a network type of its own (TX013).
pub(crate) struct Cut(Box<dyn Fn() + Send + Sync>);

impl Cut {
    pub(crate) fn new(shut: impl Fn() + Send + Sync + 'static) -> Self {
        Self(Box::new(shut))
    }
}

impl std::fmt::Debug for Cut {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Cut")
    }
}

/// What a tunnel's threads and its root share: why it must stop, its
/// downstream bound, and how to shut its sockets.
#[derive(Debug)]
pub(crate) struct Handle {
    stop: Mutex<Option<EgressDisposition>>,
    cap: AtomicU64,
    cuts: Mutex<Vec<Cut>>,
}

impl Handle {
    fn new(cap: Option<u64>) -> Self {
        Self {
            stop: Mutex::new(None),
            cap: AtomicU64::new(cap.unwrap_or(u64::MAX)),
            cuts: Mutex::new(Vec::new()),
        }
    }

    /// Why the tunnel must stop, once it must.
    pub(crate) fn stopped(&self) -> Option<EgressDisposition> {
        *self.stop.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The most bytes it may still carry back, in all.
    pub(crate) fn cap(&self) -> u64 {
        self.cap.load(Ordering::SeqCst)
    }

    fn narrow(&self, cap: Option<u64>) {
        if let Some(cap) = cap {
            self.cap.fetch_min(cap, Ordering::SeqCst);
        }
    }

    /// Stop it for `why`: the first reason is kept, and every socket it
    /// holds is shut both ways, so neither direction moves another byte.
    fn halt(&self, why: EgressDisposition) {
        {
            let mut stop = self.stop.lock().unwrap_or_else(PoisonError::into_inner);
            if stop.is_none() {
                *stop = Some(why);
            }
        }
        for cut in &*self.cuts.lock().unwrap_or_else(PoisonError::into_inner) {
            (cut.0)();
        }
    }

    /// Hold a way to shut one of its sockets, so a stop shuts it too -- the
    /// client's at admission, the dialled connection's once dialled. A stop
    /// that came first shuts it now.
    pub(crate) fn hold(&self, cut: Cut) {
        let mut cuts = self.cuts.lock().unwrap_or_else(PoisonError::into_inner);
        if self.stopped().is_some() {
            (cut.0)();
        }
        cuts.push(cut);
    }
}

/// A tunnel the authorisation admitted.
#[derive(Debug)]
pub(crate) struct Admitted {
    id: u64,
    target: usize,
    invocation: InvocationId,
    /// What the tunnel's threads and the root share.
    pub(crate) handle: Arc<Handle>,
    /// Where its bytes are counted.
    pub(crate) bytes: Arc<Bytes>,
}

/// Why a CONNECT was refused, and the destination it named, when it named
/// one of the authorisation's.
pub(crate) type Refused = (EgressDisposition, Option<usize>);

impl Root {
    fn state(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Hold `egress` for `environment`'s workload `invocation` until
    /// [`Self::finish`]. It starts exposed when the authority says so or the
    /// root already is.
    ///
    /// # Errors
    ///
    /// [`BrokerRefusal::WorkloadInUse`] when the environment's workload
    /// already holds one.
    pub(crate) fn install(
        &self,
        environment: &str,
        invocation: &InvocationId,
        egress: WorkloadEgress,
    ) -> Result<(), BrokerRefusal> {
        let mut state = self.state();
        if state.members.contains_key(environment) {
            return Err(BrokerRefusal::WorkloadInUse);
        }
        let targets = egress.targets.len();
        let member = Member {
            invocation: invocation.clone(),
            seen: egress.targets.iter().map(|t| t.seen).collect(),
            exposed: egress.exposed || state.exposed,
            reached_origin: false,
            open: BTreeMap::new(),
            tallies: (0..targets).map(|_| Tally::default()).collect(),
            unattributed: Counts::new(),
            egress,
        };
        state.members.insert(environment.to_owned(), member);
        Ok(())
    }

    /// The first decision, before the name is resolved: an authorisation is
    /// in force for the environment, it names the destination, and its cell
    /// allows some address.
    ///
    /// # Errors
    ///
    /// `NOT_AUTHORISED`, or `POLICY_DENIED` with the destination.
    pub(crate) fn consider(
        &self,
        environment: &str,
        (host, port): (&str, u16),
    ) -> Result<usize, Refused> {
        let state = self.state();
        let member = state
            .members
            .get(environment)
            .ok_or((EgressDisposition::NotAuthorised, None))?;
        let target = member
            .egress
            .index_of(host, port)
            .ok_or((EgressDisposition::NotAuthorised, None))?;
        let seen = member.seen.get(target).copied().unwrap_or(false);
        if member.egress.allows_some(target, seen, member.exposed) {
            Ok(target)
        } else {
            Err((EgressDisposition::PolicyDenied, Some(target)))
        }
    }

    /// The second decision, with the pinned answer: every address allowed in
    /// the cell that applies **now**, under the lock -- and the tunnel
    /// registered, so an exposure re-checks it and the workload's end stops
    /// it.
    ///
    /// # Errors
    ///
    /// `POLICY_ADDRESS_DENIED`, or `NOT_AUTHORISED` when the authorisation
    /// is no longer in force.
    pub(crate) fn admit(
        &self,
        environment: &str,
        target: usize,
        (pinned, client): (&[Address], Cut),
    ) -> Result<Admitted, Refused> {
        let mut state = self.state();
        let id = state.next;
        state.next = state.next.saturating_add(1);
        let member = state
            .members
            .get_mut(environment)
            .ok_or((EgressDisposition::NotAuthorised, None))?;
        let addresses: Vec<Address> = pinned.to_vec();
        let seen = member.seen.get(target).copied().unwrap_or(false);
        let allowed = member
            .egress
            .allows_all(target, (seen, member.exposed), &addresses);
        let tally = member
            .tallies
            .get_mut(target)
            .ok_or((EgressDisposition::NotAuthorised, None))?;
        for address in &addresses {
            tally.address(*address, allowed);
        }
        if !allowed {
            return Err((EgressDisposition::PolicyAddressDenied, Some(target)));
        }
        let bytes = Arc::clone(&tally.bytes);
        let handle = Arc::new(Handle::new(member.egress.tunnel_cap(
            target,
            seen,
            member.exposed,
        )));
        handle.hold(client);
        member.open.insert(
            id,
            Open {
                target,
                seen,
                addresses,
                handle: Arc::clone(&handle),
            },
        );
        Ok(Admitted {
            id,
            target,
            invocation: member.invocation.clone(),
            handle,
            bytes,
        })
    }

    /// The first byte an origin sent back on `admitted`'s tunnel, before it
    /// is forwarded: the destination is reached for its workload, and the
    /// root's exposure transition happens if it has not (module docs).
    /// Whether this tunnel may still carry it.
    pub(crate) fn origin_byte(&self, environment: &str, admitted: &Admitted) -> bool {
        let mut state = self.state();
        let Some(member) = state.members.get_mut(environment) else {
            return false;
        };
        if member.invocation != admitted.invocation
            || !member.open.contains_key(&admitted.id)
            || admitted.handle.stopped().is_some()
        {
            return false;
        }
        if let Some(seen) = member.seen.get_mut(admitted.target) {
            *seen = true;
        }
        if let Some(tally) = member.tallies.get_mut(admitted.target) {
            tally.reached = true;
        }
        member.reached_origin = true;
        if !state.exposed {
            state.exposed = true;
            for (name, member) in &mut state.members {
                member.exposed = true;
                let egress = &member.egress;
                for (id, open) in &member.open {
                    // The tunnel this byte came over has reached its
                    // destination: it is held to the seen cell. Every other
                    // open tunnel keeps the novelty it was admitted with --
                    // the stricter, even for the same destination.
                    let delivering = name.as_str() == environment && *id == admitted.id;
                    let seen = open.seen || delivering;
                    if egress.allows_all(open.target, (seen, true), &open.addresses) {
                        open.handle
                            .narrow(egress.tunnel_cap(open.target, seen, true));
                    } else {
                        open.handle.halt(EgressDisposition::ExposureRevoked);
                    }
                }
            }
        }
        admitted.handle.stopped().is_none()
    }

    /// A CONNECT on `environment` ended `disposition`: counted for its
    /// workload -- against the destination it named, when it named one --
    /// and its tunnel, if it had one, no longer open.
    pub(crate) fn ended(
        &self,
        environment: &str,
        (target, admitted): (Option<usize>, Option<&Admitted>),
        disposition: EgressDisposition,
    ) {
        let mut state = self.state();
        let Some(member) = state.members.get_mut(environment) else {
            return;
        };
        if let Some(admitted) = admitted {
            // A tunnel of a workload that has ended was counted when it was
            // stopped; it is not this workload's.
            if member.invocation != admitted.invocation
                || member.open.remove(&admitted.id).is_none()
            {
                return;
            }
        }
        match target.and_then(|t| member.tallies.get_mut(t)) {
            Some(tally) => count(&mut tally.dispositions, disposition),
            None => count(&mut member.unattributed, disposition),
        }
    }

    /// `environment`'s workload `invocation` has ended: its authorisation is
    /// removed, its open tunnels are stopped (`WORKLOAD_ENDED`), and what its
    /// tunnels did is returned. `None` when it held none.
    pub(crate) fn finish(
        &self,
        environment: &str,
        invocation: &InvocationId,
    ) -> Option<WorkloadEgressReport> {
        let mut state = self.state();
        if state
            .members
            .get(environment)
            .is_none_or(|m| &m.invocation != invocation)
        {
            return None;
        }
        let mut member = state.members.remove(environment)?;
        for open in std::mem::take(&mut member.open).into_values() {
            open.handle.halt(EgressDisposition::WorkloadEnded);
            if let Some(tally) = member.tallies.get_mut(open.target) {
                count(&mut tally.dispositions, EgressDisposition::WorkloadEnded);
            }
        }
        report(&member)
    }
}

fn counts(counts: &Counts) -> Option<EgressCountList> {
    EgressCountList::new(
        counts
            .values()
            .map(|(disposition, n)| {
                Some(EgressCount {
                    disposition: *disposition,
                    count: EgressCountValue::new(*n)?,
                })
            })
            .collect::<Option<Vec<_>>>()?,
    )
}

fn report(member: &Member) -> Option<WorkloadEgressReport> {
    let mut targets = Vec::with_capacity(member.tallies.len());
    for tally in &member.tallies {
        let addresses = tally
            .addresses
            .iter()
            .map(|(address, allowed, refused)| {
                Some(EgressAddressUse {
                    address: EgressAddress::new(address_text(address))?,
                    allowed: EgressCountValue::new(*allowed)?,
                    refused: EgressCountValue::new(*refused)?,
                })
            })
            .collect::<Option<Vec<_>>>()?;
        targets.push(WorkloadEgressTargetReport {
            reached: tally.reached,
            dispositions: counts(&tally.dispositions)?,
            bytes_upstream: ByteCount::new(tally.bytes.up.load(Ordering::SeqCst))?,
            bytes_downstream: ByteCount::new(tally.bytes.down.load(Ordering::SeqCst))?,
            addresses: EgressAddressUses::new(addresses)?,
            addresses_omitted: EgressCountValue::new(tally.omitted)?,
        });
    }
    Some(WorkloadEgressReport {
        exposed: member.reached_origin,
        targets: WorkloadEgressTargetReports::new(targets)?,
        unattributed: counts(&member.unattributed)?,
    })
}
