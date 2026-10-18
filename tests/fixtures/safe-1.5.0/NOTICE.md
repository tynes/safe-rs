# Safe v1.5.0 build artifacts

These files contain the unmodified `bytecode` and `deployedBytecode` of Safe
v1.5.0 contracts, copied from the published npm package
`@safe-global/safe-smart-account@1.5.0`
(`build/artifacts/contracts/**`, tarball integrity
`sha512-VIMWxoeY/kNuZVsQVvAeOFKcQS3eojCXg0ecGnesBSLn5ypYshmBhVEEU5XiurJJGTs/MrcoLTbTxhs9W9GvdQ==`).

The tests deploy them to a local Anvil chain through the deterministic CREATE2
deployer, so the addresses differ from the canonical ones. In v1.5.0,
`DebugTransactionGuard` implements both the transaction guard and the module
guard interface, so it can be set with `setGuard` and `setModuleGuard`.

The Safe contracts are licensed under the GNU Lesser General Public License
v3.0 (LGPL-3.0-only) by Safe Ecosystem Foundation. Source:
<https://github.com/safe-global/safe-smart-account/tree/v1.5.0>.
