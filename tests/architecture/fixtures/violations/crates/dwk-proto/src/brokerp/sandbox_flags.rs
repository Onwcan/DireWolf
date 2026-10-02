// VIOLATES TX036: a private-wire field carrying raw runtime flags.
wire_struct! {
    EnvironmentPrepareAuthorisation: reject {
        required docker_args: RuntimeArgs,
        required extra_flags: RuntimeArgs,
    }
}
