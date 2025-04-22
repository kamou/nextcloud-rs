# [WIP] nextcloud-rs

Rust based Nextcloud client library and tools.

Apps:

- [x] Passwords client (`ncpass`).
  - [x] List passwords (`ncpass list`).
  - [x] Find passwords (`ncpass find keyword`)
  - [x] Get password details (`ncpass get id [--username] [--url] [--notes] [--password] [--label]`)
  - [x] Set password details (`ncpass set id [--username USERNAME] [--url URL] [--notes NOTES] [--password PASSWORD] [--label LABEL]`)
  - [ ] Storing master password in your local keyring: requires keyring-rs to avoid leaving passwords in memory, see [here](https://github.com/open-source-cooperative/keyring-rs/issues/251), I might add it as an optional feature in the future.
- [ ] Quick Share (`ncshare /local/path/to/file [/remote/path/to/folder/]`).
- [ ] Files upload/download (`ncpush`/`ncpull`)
- [ ] Contacts (`ncfolks`)

Library Features:

- [x] Login Flow v2
- [x] Passwords API: Read access.
- [x] Passwords API: Write access.
- [ ] Files
- [ ] Contacts
- [ ] and more...
