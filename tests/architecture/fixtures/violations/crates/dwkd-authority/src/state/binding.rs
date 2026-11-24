//! FIXTURE: an approval binding that allows, writes, permits, reaches the
//! broker and answers a DWKP message: a second authorization path (TX066).
//! This comment names Effect::Allow, UPDATE and the broker and is no finding.

pub fn allowed(effect: Effect) -> bool { effect == Effect::Allow }
pub const SPENT: &str = "UPDATE run SET state = 'RELEASED' WHERE run_id = ?1";
pub fn spendable(plan: &Plan) -> bool { plan.permits() }
pub fn ask(link: &Link) { link.broker().perform(); }
pub fn answer(body: &DwkpBody) {}
