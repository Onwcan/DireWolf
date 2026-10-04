// VIOLATES TX036: a private-wire field carrying raw runtime flags.
wire_struct! {
    EnvironmentPrepareAuthorisation: reject {
        required docker_args: RuntimeArgs,
        required extra_flags: RuntimeArgs,
        // M5b: the egress grant naming its own resolver and exceptions.
        optional resolver: ResolverSpec,
        optional egress_exceptions: AddressList,
    }
}
