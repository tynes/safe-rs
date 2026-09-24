# Safe v1.4.1 build artifacts

These files contain the unmodified `bytecode` and `deployedBytecode` of Safe
v1.4.1 contracts, copied from the published npm package
`@safe-global/safe-contracts@1.4.1`
(`build/artifacts/contracts/**`, tarball integrity
`sha512-fP1jewywSwsIniM04NsqPyVRFKPMAuirC3ftA/TA4X3Zc5EnwQp/UCJUU2PL/37/z/jMo8UUaJ+pnFNWmMU7dQ==`).

The runtime code of `Safe`, `SafeL2`, `SafeProxyFactory`, `MultiSendCallOnly`
and `CompatibilityFallbackHandler` is byte-identical to the canonical
deployments on Ethereum mainnet. The tests deploy them to a local Anvil chain
through the deterministic CREATE2 deployer, so the addresses differ from the
canonical ones while the code does not.

The Safe contracts are licensed under the GNU Lesser General Public License
v3.0 (LGPL-3.0-only) by Safe Ecosystem Foundation. Source:
<https://github.com/safe-global/safe-smart-account/tree/v1.4.1>.
