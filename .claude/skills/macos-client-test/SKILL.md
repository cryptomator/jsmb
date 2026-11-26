---
name: macos-client-test
description: Test jSMB against the macOS SMB client (smbfs) — starts the `run` harness, mounts its share, runs file operations on the mount while watching the server log, guides the user through manual tests in Finder, and tears down again. Use when the user asks to "test with the macOS client", "mount the server and test it", "check that Finder / macOS still works", or after a change to request validation, access checks, credits, negotiation or compound handling, which smbj and smbclient exercise differently than macOS does.
---

# Test against the macOS SMB client

The macOS client sends requests that neither `smbj` (the `*IT` tests) nor Samba's `smbclient` (the `interop-scenario` skill) produce: related compound requests, byte-range locks, AppleDouble companion files, its own mapping of characters that are illegal in SMB names. This skill mounts the harness' share with it. You run shell commands against the mount yourself (step 2) and have the user do in Finder what you can't (step 3), watching the server log throughout (step 4).

macOS only. Two helper scripts do everything that needs to happen outside the sandbox.

## Procedure

### 1. Start the server and mount the share

```bash
.claude/skills/macos-client-test/start.sh
```

Run it **outside the sandbox**: the sandbox blocks `mount_smbfs` and hides the listening server from `lsof`. It takes about a minute when it has to start the server, as the harness runs the test suite first — set a timeout of at least 240 s.

It prints:

- `SERVER=started` or `SERVER=reused` (a harness was listening on port 4446 already)
- `LOG=<path>` — the server log. Empty if the server was reused and not started by this script; its log is then wherever it got started, e.g. `/tmp/jsmb-harness.log` for the interop harness.
- `MOUNT=<path>` — the mount point, `/private/tmp/claude/jsmb-macos-client/mount`. Sandboxed commands can read and write there, so nothing has to be added to the session. Should a write fail with "Operation not permitted" nonetheless, ask the user to run `/add-dir <mount point>`.

**If the script may not run outside the sandbox, or prints `MOUNT-FAILED`:** hand the mounting to the user. Give them one of these to paste into the prompt, complete with credentials (those of `RunIT`: domain `DOMAIN`, user `user`, password `password`, share `data`):

```
! .claude/skills/macos-client-test/start.sh
```

or, with the server running already, the bare mount command that the script printed:

```
! mount_smbfs '//DOMAIN;user:password@localhost:4446/data' '<mount point>'
```

If the user would rather mount with Finder (`smb://localhost:4446/data`), the share shows up as `/Volumes/data`, which the sandbox doesn't let you write to. Ask them to run `/add-dir /Volumes/data` and use that as the mount point.

### 2. Run the shell tests

Work in a directory of your own on the mount (`<mount>/jsmb-test`) and run the commands **inside the sandbox**. What to run depends on the change under test; the full catalogue:

| Area | Commands | Expect |
|---|---|---|
| Create / append / truncate | `echo hello > f`, `echo more >> f`, `truncate -s 3 f`, `cat f` | content and size as written |
| Large file (multi-credit READ/WRITE) | `dd if=/dev/urandom of=$TMPDIR/big.bin bs=1m count=300`, `cp` to the mount and back, `shasum -a 256` both | equal checksums |
| Timestamps | `touch -t 202001010000 f`, `stat -f "%Sm" f` | 1 Jan 2020 |
| Rename / move | `mv f g`, `mv g sub/g`, `mv sub/g g`, `mv sub sub2` (non-empty folder) | all succeed |
| Replace | `echo v2 > .tmp && mv -f .tmp f`, `cp -f other f` | new content |
| Delete | `rm f`, `rmdir empty`, `rmdir non-empty`, `rm -r tree` | `rmdir non-empty` fails with "Directory not empty" |
| Names | files named `a:b.txt`, `what?.txt`, `star*.txt`, `trailing.`, with umlauts, with 255 characters | all get created (macOS maps the illegal characters itself) |
| Listing | create 400 files in a folder, `ls \| wc -l`, `cp -R` the folder out | 400 each |

Remove what you put into `$TMPDIR` when done. The share itself is a temp dir that goes away with the server.

### 3. Have the user test with Finder

Finder talks to the server differently than the shell does: it browses with related compound requests, asks for more kinds of information, and saves files by writing a temporary one and renaming it over the original. You can't drive it — `open` and `osascript` are blocked in the sandbox — so the user does, one batch at a time, and you watch the log.

**Prepare** a folder for it, `<mount>/jsmb-test/finder`, with:

- `notes.txt` — a few lines of text
- `many/` — 400 small files
- `full/` — two files
- `empty/`

**Tell the user how to get there:** in Finder, *Go → Go to Folder…* (⇧⌘G), then paste the full path of `<mount>/jsmb-test/finder`.

**Then, for each batch** you want covered:

1. Note the length of the log: `wc -l < "$LOG"`.
2. Give the user the steps of that one batch as a numbered list, with what they should see. Ask them to tell you when they are done and to mention anything unexpected: an error dialog, a long wait, an item that is missing or shown twice.
3. End your turn and wait. Don't run anything on the mount in the meantime, as it would mix into the log.
4. Once they have answered, evaluate the log from the noted line on (step 4 below) and check the outcome on the mount from the shell. Report both before moving on to the next batch.

| Batch | Steps for the user | They should see | Check from the shell |
|---|---|---|---|
| Browse | Open `many`. Switch to list view (⌘2) and click the *Name* column to sort. Select a file and press Space. Go back, select `notes.txt`, press ⌘I. Do the same for the folder `full`. | 400 items. A preview of the file's text. Info windows with size and dates. | nothing changed on the mount |
| Copy | Drag a file and a folder with a few files from the Desktop into `finder`. Drag `notes.txt` from `finder` onto the Desktop. | Both copies finish without a dialog. | `ls -la` shows the new items (and `._` companions, if they had extended attributes) |
| Edit | Double-click `notes.txt` (TextEdit), add a line, save with ⌘S, close the window. | No "could not be saved" dialog. | `cat notes.txt` shows the new line |
| Rename and move | Select `notes.txt`, press Return, rename it to `renamed.txt`. Drag it into `empty`. Select a file in `full` and press ⌘D. Press ⇧⌘N for a new folder. | Each change shows up right away. | `ls -R` matches |
| Delete | Select a file and press ⌘⌫, then do the same for the folder `full`. Finder asks whether to delete immediately, as a network share has no Trash: confirm. | Both disappear. | both are gone |
| Eject | Click the eject symbol next to the server in the sidebar (or skip this and let `stop.sh` unmount). | The volume disappears. | `mount` no longer lists it; go on to step 5 |

Afterwards remind the user to remove what they copied to their Desktop.

### 4. Watch the server log

Note the log's length before a group of commands (`wc -l < "$LOG"`) and look at what got added afterwards. Filters worth running:

```bash
# warnings and dropped connections
grep -E "WARN|ERROR|Exception|isconnect" "$LOG" | grep -v "Unknown module"
# every response that isn't STATUS_SUCCESS, counted per command and status; replace 1 by the line to start from
tail -n +1 "$LOG" | grep -o -E "Command 0x[0-9a-f]+ \(messageId=[0-9]+\) answered with status 0x[0-9a-f]+" | cut -d' ' -f2,7 | sort | uniq -c | sort -rn
# compounded requests, counted by shape
tail -n +1 "$LOG" | grep -o -E "Compounded request of [0-9]+ commands, [0-9]+ of them related" | sort | uniq -c | sort -rn
# what macOS asked for that jSMB doesn't implement
grep -o -E "unsupported class 0x[0-9a-f]+|Unhandled FSCTL/IOCTL 0x[0-9a-f]+" "$LOG" | sort | uniq -c
```

`TcpConnection` logs every non-success response as `Command 0x<command> (messageId=<n>) answered with status 0x<status>`, whichever check or handler it stems from, and every packet that holds more than one command as `Compounded request of <n> commands, <m> of them related`. Commands are numbered as in `smb2.Command` (`0x5` CREATE, `0x6` CLOSE, `0x8` READ, `0x9` WRITE, `0xa` LOCK, `0xe` QUERY_DIRECTORY, `0x10` QUERY_INFO, `0x11` SET_INFO), statuses as in `common.NTStatus`.

Routine, with nothing wrong:

| Command, status | Meaning |
|---|---|
| `0x1 0xc0000016` | SESSION_SETUP, `STATUS_MORE_PROCESSING_REQUIRED`: the first leg of authentication |
| `0x5 0xc0000034` | CREATE, `STATUS_OBJECT_NAME_NOT_FOUND`: macOS probing for a name |
| `0x6`, `0x10`, `0x11` with `0xc0000034` | CLOSE, QUERY_INFO or SET_INFO related to such a CREATE, which fail with its status |
| `0x8 0xc0000011` | READ, `STATUS_END_OF_FILE` |
| `0xe 0xc000000f`, `0xe 0x80000006` | QUERY_DIRECTORY, `STATUS_NO_SUCH_FILE` (lookup of a missing name) and `STATUS_NO_MORE_FILES` |
| `0xa 0xc00000bb` | LOCK, `STATUS_NOT_SUPPORTED`: not implemented, sent by the thousands |
| `0x10 0xc00000bb` | QUERY_INFO for an info type jSMB doesn't serve (security, quota), `STATUS_NOT_SUPPORTED`: about one per file that `cp` copies |
| `0x11 0xc0000003` | SET_INFO with `FileAllocationInformation`, `STATUS_INVALID_INFO_CLASS` |
| `0xb 0xc0000010` | IOCTL `0x140078` during mount, `STATUS_INVALID_DEVICE_REQUEST` |
| `0x11 0xc0000101` | SET_INFO, `STATUS_DIRECTORY_NOT_EMPTY`: the `rmdir non-empty` test |

Worth a closer look, as they point at a check that is stricter than macOS expects: `0xc0000022` (`STATUS_ACCESS_DENIED`), `0xc000000d` (`STATUS_INVALID_PARAMETER`), `0xc0000033` (`STATUS_OBJECT_NAME_INVALID`), `0xc0000008` (`STATUS_INVALID_HANDLE`), `0xc0000128` (`STATUS_FILE_CLOSED`), and `STATUS_NOT_SUPPORTED` for any command other than LOCK and QUERY_INFO.

### 5. Tear down

```bash
.claude/skills/macos-client-test/stop.sh
```

Outside the sandbox again. It unmounts, unless the user ejected the volume already, and stops the server if `start.sh` was what started it. `stop.sh --force` unmounts while files are still open; the server sees that as a lost connection, which makes it a test of its own (opens get closed, delete-on-close files removed).

## Reporting

Summarize for the user:

- **Client side**: which operations succeeded, which failed and with what error — yours from the shell and theirs from Finder.
- **Server side**: warnings, dropped connections, refusals beyond the routine ones, and the unsupported requests macOS sent.
- **Not covered**: what you didn't run, and the Finder batches that were skipped.

## Gotchas

- **Expected noise in the log.** macOS sends `LOCK` (command `0xa`) thousands of times, `SET_INFO` with `FileAllocationInformation` (class `0x13`) and FSCTL `0x140078`. jSMB implements none of these and macOS carries on.
- **Maven errors at the end of the log** are what stopping the harness looks like: `stop.sh` terminates the forked test JVM, which Maven reports as a failed build.
- **`._name` files** are AppleDouble companions that macOS creates for extended attributes, as the share doesn't offer named streams. They get renamed and deleted along with their main file. `rm -r` therefore prints "No such file or directory" for companions that went away with a file it had removed just before, and exits non-zero although the tree is gone.
- **A name of more than 255 characters** is refused by macOS itself and never reaches the server.
- **Finder leaves `.DS_Store` files** (and their `._` companions) in every folder it shows. They are not a sign of trouble.
- **Never clean up with a recursive delete on a path you didn't create.** The mount point lives outside the project on purpose: a `mvn clean` or `git clean` running across a mounted share would delete the share's content.
- **Port 4446 is shared with the `interop-scenario` skill.** If its harness is running, `start.sh` reuses it, and `stop.sh` leaves it alone.
