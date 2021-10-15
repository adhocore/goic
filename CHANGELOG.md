## [v0.0.11](https://github.com/adhocore/goic/releases/tag/v0.0.11) (2021-10-15)

### Features
- Add signout method, it needs to be called programattically (Jitendra Adhikari) [_b1783b4_](https://github.com/adhocore/goic/commit/b1783b4)

### Bug Fixes
- Provider may not even suppport signout (Jitendra Adhikari) [_25dde2a_](https://github.com/adhocore/goic/commit/25dde2a)

### Miscellaneous
- Signout example (Jitendra Adhikari) [_c7ee172_](https://github.com/adhocore/goic/commit/c7ee172)

### Documentations
- For signout (Jitendra Adhikari) [_8a55865_](https://github.com/adhocore/goic/commit/8a55865)
- Update todo (Jitendra) [_a3d6e4a_](https://github.com/adhocore/goic/commit/a3d6e4a)
- Update (Jitendra) [_f4b2b18_](https://github.com/adhocore/goic/commit/f4b2b18)


## [v0.0.10](https://github.com/adhocore/goic/releases/tag/v0.0.10) (2021-10-14)

### Features
- Support refresh_token grant (Jitendra Adhikari) [_27b2267_](https://github.com/adhocore/goic/commit/27b2267)

### Internal Refactors
- Rename func arg, fix auth code grant (Jitendra Adhikari) [_a8ed467_](https://github.com/adhocore/goic/commit/a8ed467)
- Make RequestAuth able to be used standalone from outside (Jitendra Adhikari) [_cfec49a_](https://github.com/adhocore/goic/commit/cfec49a)

### Miscellaneous
- Use printf (Jitendra Adhikari) [_0cb25d8_](https://github.com/adhocore/goic/commit/0cb25d8)
- Update docs, cleanup unused (Jitendra Adhikari) [_1bdb0cd_](https://github.com/adhocore/goic/commit/1bdb0cd)

### Documentations
- Add detailed API docs for standalone/manual usage (Jitendra Adhikari) [_26ac14e_](https://github.com/adhocore/goic/commit/26ac14e)
- Add yahoo docs (Jitendra Adhikari) [_af8126f_](https://github.com/adhocore/goic/commit/af8126f)


## [v0.0.9](https://github.com/adhocore/goic/releases/tag/v0.0.9) (2021-10-14)

### Features
- Add Yahoo provider (Jitendra Adhikari) [_d9d12af_](https://github.com/adhocore/goic/commit/d9d12af)
- Support ecdsa key/algo (Jitendra Adhikari) [_68866a1_](https://github.com/adhocore/goic/commit/68866a1)
- Support ecdsa key/algo (Jitendra Adhikari) [_1079448_](https://github.com/adhocore/goic/commit/1079448)

### Bug Fixes
- Key check order/clause for rsa and ec (Jitendra Adhikari) [_9f29c79_](https://github.com/adhocore/goic/commit/9f29c79)

### Internal Refactors
- Delete state immediately, fix error HTML (Jitendra Adhikari) [_3db1dff_](https://github.com/adhocore/goic/commit/3db1dff)

### Miscellaneous
- Update yahoo example (Jitendra Adhikari) [_f223c06_](https://github.com/adhocore/goic/commit/f223c06)

### Documentations
- Add yahoo demo (Jitendra Adhikari) [_803e8e4_](https://github.com/adhocore/goic/commit/803e8e4)


## [v0.0.8](https://github.com/adhocore/goic/releases/tag/v0.0.8) (2021-10-13)

### Internal Refactors
- Add/use errorHTML() helper, validate provider, show retry url (Jitendra Adhikari) [_0c5431e_](https://github.com/adhocore/goic/commit/0c5431e)
- Extract user and token struct and func (Jitendra Adhikari) [_931cb6e_](https://github.com/adhocore/goic/commit/931cb6e)
- Extract user struct, unset state, log if verbose (Jitendra Adhikari) [_1192822_](https://github.com/adhocore/goic/commit/1192822)

### Documentations
- Update todo (Jitendra) [_b5fc8c2_](https://github.com/adhocore/goic/commit/b5fc8c2)


## [v0.0.7](https://github.com/adhocore/goic/releases/tag/v0.0.7) (2021-10-12)

### Bug Fixes
- Unset state only after successfully used (Jitendra Adhikari) [_6155d1d_](https://github.com/adhocore/goic/commit/6155d1d)


## [v0.0.6](https://github.com/adhocore/goic/releases/tag/v0.0.6) (2021-10-12)

### Features
- Add ready instances of providers for google and microsoft (Jitendra Adhikari) [_55c2ba4_](https://github.com/adhocore/goic/commit/55c2ba4)
- Add addProvider() (Jitendra Adhikari) [_a6b1524_](https://github.com/adhocore/goic/commit/a6b1524)

### Bug Fixes
- Switch to form-url-encoded from json (Jitendra Adhikari) [_1a4bc17_](https://github.com/adhocore/goic/commit/1a4bc17)

### Internal Refactors
- Google example (Jitendra Adhikari) [_cc94831_](https://github.com/adhocore/goic/commit/cc94831)
- AQAB is frequently used and is is 65537 (Jitendra Adhikari) [_0ff7b85_](https://github.com/adhocore/goic/commit/0ff7b85)
- Update json meta, error msg fmt, cleanup imports (Jitendra Adhikari) [_c8e4b92_](https://github.com/adhocore/goic/commit/c8e4b92)

### Miscellaneous
- Add example with all providers (Jitendra Adhikari) [_ee4e86b_](https://github.com/adhocore/goic/commit/ee4e86b)
- Add microsoft example (Jitendra Adhikari) [_255794a_](https://github.com/adhocore/goic/commit/255794a)

### Documentations
- Update example, login anchor and demo section (Jitendra Adhikari) [_ab52e67_](https://github.com/adhocore/goic/commit/ab52e67)


## [v0.0.5](https://github.com/adhocore/goic/releases/tag/v0.0.5) (2021-10-11)

### Features
- Add base64 url decoder and use from parseModulo(), parseExponent() (Jitendra Adhikari) [_fdfd3af_](https://github.com/adhocore/goic/commit/fdfd3af)

### Internal Refactors
- Use shorthand func param types, update verbose msg format (Jitendra Adhikari) [_19a1bca_](https://github.com/adhocore/goic/commit/19a1bca)
- Extract verifyClaims() from verifyToken() (Jitendra Adhikari) [_8672ae9_](https://github.com/adhocore/goic/commit/8672ae9)

### Documentations
- Update demo section (Jitendra) [_2095357_](https://github.com/adhocore/goic/commit/2095357)
- Add demo URL (Jitendra) [_f0afa31_](https://github.com/adhocore/goic/commit/f0afa31)
- Minor updates (Jitendra) [_8dfb403_](https://github.com/adhocore/goic/commit/8dfb403)


## [v0.0.4](https://github.com/adhocore/goic/releases/tag/v0.0.4) (2021-10-11)

### Miscellaneous
- Fix lf (Jitendra Adhikari) [_1d9106b_](https://github.com/adhocore/goic/commit/1d9106b)
- Update editorconfig (Jitendra Adhikari) [_cccf302_](https://github.com/adhocore/goic/commit/cccf302)

### Documentations
- Add badges, fix lf (Jitendra Adhikari) [_3019df0_](https://github.com/adhocore/goic/commit/3019df0)


## [v0.0.3](https://github.com/adhocore/goic/releases/tag/v0.0.3) (2021-10-11)

### Internal Refactors
- Move currentUrl() to util (Jitendra Adhikari) [_2423d7d_](https://github.com/adhocore/goic/commit/2423d7d)

### Documentations
- Update todo list (Jitendra Adhikari) [_93cdafb_](https://github.com/adhocore/goic/commit/93cdafb)
- Add func docs (Jitendra Adhikari) [_8fa088e_](https://github.com/adhocore/goic/commit/8fa088e)


## [v0.0.2](https://github.com/adhocore/goic/releases/tag/v0.0.2) (2021-10-11)

### Internal Refactors
- Switch to jwt v4 (Jitendra Adhikari) [_5888654_](https://github.com/adhocore/goic/commit/5888654)

### Miscellaneous
- Use jwt v4 (Jitendra Adhikari) [_54de05e_](https://github.com/adhocore/goic/commit/54de05e)


## [v0.0.1](https://github.com/adhocore/goic/releases/tag/v0.0.1) (2021-10-11)

### Features
- Add google example (Jitendra Adhikari) [_49c2518_](https://github.com/adhocore/goic/commit/49c2518)
- Add goic, the main program (Jitendra Adhikari) [_90839b1_](https://github.com/adhocore/goic/commit/90839b1)
- Define provider struct, add related functionality (Jitendra Adhikari) [_21fe302_](https://github.com/adhocore/goic/commit/21fe302)
- Add util for common tasks (Jitendra Adhikari) [_5896ea2_](https://github.com/adhocore/goic/commit/5896ea2)

### Miscellaneous
- Add go mod stuffs (Jitendra Adhikari) [_3bdcd00_](https://github.com/adhocore/goic/commit/3bdcd00)
- Add license (Jitendra Adhikari) [_2963a4b_](https://github.com/adhocore/goic/commit/2963a4b)
- Add dotfiles (Jitendra Adhikari) [_8f76c5c_](https://github.com/adhocore/goic/commit/8f76c5c)

### Documentations
- Add README (Jitendra Adhikari) [_252eae9_](https://github.com/adhocore/goic/commit/252eae9)
