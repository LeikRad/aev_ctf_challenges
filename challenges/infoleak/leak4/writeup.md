# leak4 - Secret recoverable from exposed .git history

| | |
|---|---|
| **Challenge** | leak4 |
| **Category** | INFOLEAK |
| **Points / Difficulty** | 200 / medium |
| **Target** | http://leak4.chal.deti:8013 ("Build host") |
| **Leak class** | VCS metadata exposure (`.git/`) - secret in commit history |

## Hint
> A "build host" that serves its own directory. Version control is a journal.
> All the changes kept, even the ones thrown away - read the old pages.

## Recon
Content discovery found `/.git/HEAD` (200) and `/app.py` (200) on 8013 - the whole
`.git` directory is served over HTTP. `/.git/HEAD` returned `ref: refs/heads/master`,
confirming a live repo. The hint stresses the flag is in **history**, not the working
tree (the current `flag.txt` is gone).

## Approach
Reconstruct the repository from the exposed `.git/` and walk the full commit history,
including diffs of deleted content. Used `git-dumper` to pull it, then `git log -p`.

## Which files do you read first, and why (task question)
Before dumping the whole repo, a few `.git` files give the fastest signal - all are
plaintext and need no object parsing:
1. **`/.git/HEAD`** - one line (`ref: refs/heads/master`): tells you the current branch
   to follow. (Already confirmed the repo is live.)
2. **`/.git/logs/HEAD`** (the reflog) - **read this first for content.** It is a
   human-readable *journal*: one line per ref update with `<old> <new> <author>
   <timestamp> <message>`. It lists **every commit the branch ever pointed to -    including ones later "removed"** - so it reveals the `temp: add flag` / `remove
   temp flag` commit hashes and messages without touching a single object. This is the
   literal "read the old pages" of the hint.
3. **`/.git/packed-refs`** + **`/.git/refs/`** - resolve branch/tag names to commit
   hashes (in case history is packed).
4. **`/.git/config`** - remotes / repo metadata (sometimes leaks internal URLs/creds).
5. Only then the **`/.git/objects/…`** (loose or packed) - the actual commit/tree/blob
   contents. Rather than fetch these by hand, `git-dumper` pulls them and lets `git`
   read them normally.

## Exploitation - the exact request
```bash
pip install git-dumper
git-dumper http://leak4.chal.deti:8013/.git ~/infoleak/loot/leak4-git
cd ~/infoleak/loot/leak4-git
git log --all --oneline
git log -p --all          # shows every commit's diff, incl. deleted files
```

## Response fragment that carried the flag
Two commits - the secret is added, then "removed", but the diff of the earlier commit
(and its message) still contains it:
```
commit e18793... temp: add flag flag{g1t_h1story_l34ks} for testing
+flag{g1t_h1story_l34ks}

commit eea9eb... chore: remove temp flag
-flag{g1t_h1story_l34ks}
```

## Flag
```
flag{g1t_h1story_l34ks}
```

## Root cause & remediation
- **Cause:** the `.git` directory was deployed into the web root, and a secret that
  was committed then deleted remains fully recoverable from history. `git rm` removes
  a file from the *working tree*, never from past commits.
- **Fix:** never ship `.git` to production (deploy build artifacts, or block
  `location ~ /\.git` at the server); if a secret was ever committed, rotate it and
  purge history (`git filter-repo` / BFG) - deletion in a later commit is not enough;
  add secret-scanning (gitleaks) to CI to catch commits before they ship.
