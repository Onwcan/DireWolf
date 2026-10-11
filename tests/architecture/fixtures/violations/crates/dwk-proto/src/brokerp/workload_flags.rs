// VIOLATES TX036: a workload on the private wire that chooses how it runs --
// as whom, with which variables, through which entrypoint, attached to what.
wire_struct! {
    WorkloadRunAuthorisation: reject {
        required run_as: ExecUser,
        optional extra_env: EnvList,
        optional entrypoint: ImagePath,
        required privileged: bool,
        required tty: bool,
    }
}
