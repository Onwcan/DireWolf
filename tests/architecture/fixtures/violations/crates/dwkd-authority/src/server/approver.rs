//! FIXTURE: the approver endpoint reaching past the approver protocol (TX065)
//! -- a DWKP decode, a dispatch, a level of its own; no finding in comments.

pub fn serve(worker: &Worker, frame: &Frame) {
    let message = dwkp::decode_frame(frame);
    worker.dispatch(caller, message);
    let level = Assurance::A2;
}
