// VIOLATES TX044: a second HTTP client in the broker, outside `http/`, which
// none of the per-hop checks stand in front of.
use ureq_proto::client::Call;

pub fn second_client(request: Request) -> Call<Prepare> {
    Call::new(request).unwrap()
}
