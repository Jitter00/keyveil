# CHANGELOG

<!-- version list -->

## v0.4.1 (2026-11-04)

### Bug Fixes

- **sandbox**: Keep other projects' agent data out of reach
  ([#9](https://github.com/Jitter00/keyveil/pull/9),
  [`e0c4fc4`](https://github.com/Jitter00/keyveil/commit/e0c4fc4dd13d6611935d362c51a0ab9c9461d418))

### Continuous Integration

- Add Claude Code GitHub workflows ([#8](https://github.com/Jitter00/keyveil/pull/8),
  [`920826d`](https://github.com/Jitter00/keyveil/commit/920826dbb99405bb65d8fc6b93b1ceb587a0d252))


## v0.4.0 (2026-11-03)

### Features

- **sandbox**: Block nested user namespaces and add Codex and Gemini profiles
  ([#7](https://github.com/Jitter00/keyveil/pull/7),
  [`2370a0b`](https://github.com/Jitter00/keyveil/commit/2370a0b963cf9dd6d7f01373816eb8102c9080a8))


## v0.3.1 (2026-11-02)

### Bug Fixes

- **sandbox**: Clear display and D-Bus variables the sandbox can't reach
  ([#6](https://github.com/Jitter00/keyveil/pull/6),
  [`026888a`](https://github.com/Jitter00/keyveil/commit/026888a97fb9689cc04f948e36376b046994c82d))

### Chores

- Sync uv.lock with 0.3.0 ([#2](https://github.com/Jitter00/keyveil/pull/2),
  [`ad9a432`](https://github.com/Jitter00/keyveil/commit/ad9a43258cc57ee487c10ef2eaace21eb5a108d4))

### Continuous Integration

- Attach release files with gh instead of publish-action
  ([#4](https://github.com/Jitter00/keyveil/pull/4),
  [`ca8c058`](https://github.com/Jitter00/keyveil/commit/ca8c0583af224b3435b3a4b71a80872bb2af9422))

- Update uv.lock in the release commit ([#3](https://github.com/Jitter00/keyveil/pull/3),
  [`de4f85a`](https://github.com/Jitter00/keyveil/commit/de4f85a659dbc5c7db796979322b007815b2aa2b))

### Documentation

- Correct the required check names in the ruleset setup
  ([#5](https://github.com/Jitter00/keyveil/pull/5),
  [`076d5f7`](https://github.com/Jitter00/keyveil/commit/076d5f77a017af0836c338f483bfa9a414483e75))


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
