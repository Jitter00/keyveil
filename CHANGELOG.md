# CHANGELOG

<!-- version list -->

## v0.3.0 (2026-11-02)

### Bug Fixes

- Hide more credentials and only trust files you alone can change
  ([`8f15e8f`](https://github.com/Jitter00/keyveil/commit/8f15e8fa0003c4731d41f54be30a3dc29bf383c2))

- **proxy**: Refuse non-loopback binds and ambiguous allowlisted paths
  ([`f5c3ace`](https://github.com/Jitter00/keyveil/commit/f5c3acebf368827ee48faadea35c6dd0c08d59be))

- **sandbox**: Allow an existing key file inside the project; pin its folders
  ([`a58edcf`](https://github.com/Jitter00/keyveil/commit/a58edcf7ca4c0941c5dfd076750ce92cec0f8393))

- **sandbox**: Attach slirp4netns through the user namespace that owns the sandbox's network
  ([`359e60e`](https://github.com/Jitter00/keyveil/commit/359e60e9097e21774eb32d04da2648412c509515))

- **sandbox**: Keep hidden paths hidden inside writable directories
  ([`5b46ab0`](https://github.com/Jitter00/keyveil/commit/5b46ab038cce2e473383cf4ed13d3f35b6e53e01))

- **sandbox**: Pin git dirs and check repositories after exit
  ([`91fbc69`](https://github.com/Jitter00/keyveil/commit/91fbc69673cdbf409d987d870c738e7294421d38))

- **sandbox**: Protect Claude Code config that runs code later
  ([`5a855f0`](https://github.com/Jitter00/keyveil/commit/5a855f0d83c6dd6f5203f3482a1466806b9fae1c))

- **sandbox**: Wait for the uid map before attaching slirp4netns; never start the agent if it fails
  ([`bfbbf27`](https://github.com/Jitter00/keyveil/commit/bfbbf275090dd577ad79b9f3ff68af15dde3a34f))

### Continuous Integration

- Refuse to release when no starting version tag exists
  ([`51c6261`](https://github.com/Jitter00/keyveil/commit/51c6261681bcf92247208a97f137a6afb31d99cc))

### Features

- **sandbox**: Give the agent its own network namespace
  ([`44aec51`](https://github.com/Jitter00/keyveil/commit/44aec51aa9c9990e0bb11443454575028f6aae65))

### Breaking Changes

- **sandbox**: The default mode needs slirp4netns, and sandboxed agents can no longer reach host
  services on 127.0.0.1 other than the proxy.


## v0.2.0 (2026-11-01)

- Initial Release
