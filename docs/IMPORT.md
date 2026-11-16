# Importing accounts

```sh
gatehouse import path/to/export.csv
```

You see a numbered preview with passwords masked, choose entries (`2,5-7`), and only those are stored. Everything else in the file is ignored.

## Formats

**Generic.** A header row with at least `username` and `password`. Recognized columns (case-insensitive):

| Field | Accepted headers |
|---|---|
| name | `name`, `title`, `account` |
| website | `url`, `website`, `login_uri`, `uri` |
| username | `username`, `user`, `login`, `email`, `login_username` |
| password | `password`, `login_password` |
| TOTP | `totp`, `otpauth`, `otp`, `login_totp` (base32 secret or `otpauth://totp/...`) |

See `examples/generic.csv`.

**Apple Passwords.** The file produced by Passwords → File → Export: `Title,URL,Username,Password,Notes,OTPAuth`. See `examples/apple-passwords.csv`. Tested against a synthetic file with that layout, not against a real export.

## What import does and does not do

- **No access is granted.** An imported account has no approved website and no grants. The URL from the file is kept as a hint; you approve a website explicitly with `gatehouse account edit <id> --approve-origin ... --login-url ...`.
- **Duplicates** (same username and same website, or same username and name): you choose skip, replace or keep both. Replace updates the password and TOTP secret and leaves approved websites and grants as they were.
- **Unsupported columns** (notes and anything unrecognized) are not stored; the result lists them per entry.
- **Passkeys and federated logins** are not in CSV exports and cannot be imported.
- **Content is data.** Names and notes are never interpreted; control characters are stripped before display; invalid or non-https addresses are dropped and reported.
- **Nothing from the file is logged.** The audit history does not record imports' contents.

## The export file

A CSV export holds every password in plain text. Export to a local, unsynced folder. After a successful import the CLI offers to delete the file. Deletion is ordinary file removal: on SSDs, APFS snapshots, Time Machine and synced folders, older copies can survive. Emptying the Trash and rotating any password you are worried about is the reliable remedy.
