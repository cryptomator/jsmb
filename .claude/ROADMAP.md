# Roadmap

What jSMB doesn't do yet but should, and known bugs. Each entry says why it matters, what it takes, and what it depends on. Spec sections refer to MS-SMB2 unless stated otherwise; verify their wording before implementing.

The numbers quoted as evidence come from one session with the macOS client on 2026-11-26 (shell tests plus six batches of Finder use, see the `macos-client-test` skill).

## Bugs

### A rename through one open doesn't reach the other opens of the file

**Symptom.** While a file is open on handle A, a client renames or moves it through handle B. Handle A keeps working on the old name:

- `Open.path` of A is stale, so `FileNameInformation` and `FileAllInformation` report the old name, and `FileInternalInformation` an `IndexNumber` hashed from the old path.
- The backend handle of A is stale as well, if the backend finds the file by path. With the `NioShare` test backend, `CLOSE` with `SMB2_CLOSE_FLAG_POSTQUERY_ATTRIB` then fails to read the attributes (`NoSuchFileException`, logged at DEBUG as "CLOSE post-query attrib failed") and returns none. Reads and writes keep working there only because the channel is open already.
- Opens of files *inside* a renamed directory are affected the same way.

**Seen with.** Finder: copying a folder in (macOS renames a `._` companion that is still open to `.smbdelete…`) and moving a file into another folder. Twice in the session; Finder didn't notice either time.

**Cause.** The path is state of the open (`Open.path`, the backend's handle), whereas it is state of the file: MS-FSA keeps the name on the `Link` that all opens of a file share. `SetInfoHandler.applyRename` updates the one open it was called on.

**Fix.**

1. Server: after a successful rename, update `Open.path` of every open in `Global` whose path is the old one or lies below it. That takes a way to enumerate all opens of a share across sessions and connections, which `Session.openTable` alone doesn't give.
2. SPI: state in the contract of `SmbOpen.rename` that a backend must keep its other handles on that file, and on anything below a renamed directory, usable. Fix `NioShare` accordingly.
3. Better, and shared with LOCK below: give the server a per-file state that all opens of a file refer to, and keep the path there.

## Features

### LOCK: byte-range locks

**Why.** macOS asks for it constantly: 29,662 `LOCK` requests in the session, all answered with `STATUS_NOT_SUPPORTED`. It carries on, but without locks two clients can write to the same range of a file unnoticed, and applications that rely on locking (Office documents, SQLite files, Time Machine sparse bundles) are at risk on a share used by more than one client.

**What it takes.** Section 2.2.26 (request), 2.2.27 (response), 3.3.5.14 (processing); MS-FSA 2.1.5.8 and 2.1.5.9 for the semantics.

- Parse `LOCK` requests: an array of `SMB2_LOCK_ELEMENT` (offset, length, flags), `LockSequenceNumber` / `LockSequenceIndex`.
- A lock table per file: shared and exclusive ranges, each owned by an open. Lock requests are all-or-nothing; a conflict yields `STATUS_LOCK_NOT_GRANTED`, an unlock of a range that isn't locked `STATUS_RANGE_NOT_LOCKED`.
- `READ` and `WRITE` have to respect the locks of other opens (`STATUS_FILE_LOCK_CONFLICT`).
- Locks go away with their open: `CLOSE`, `TREE_DISCONNECT`, `LOGOFF`, connection loss (`Open.close()` is the one place).
- Blocking locks (no `SMB2_LOCKFLAG_FAIL_IMMEDIATELY`) need the asynchronous responses described under "Prerequisites". A first step can do without: grant or refuse right away.

**Optional SPI.** The server keeps the lock table itself, so locks work between the clients of one server with any backend. A backend opts in when the locks have to hold beyond that, e.g. towards other processes that access the same storage:

```java
public interface SmbFile extends SmbOpen {

	/**
	 * Called before the server grants a byte-range lock that conflicts with no other lock it knows of.
	 * A backend that shares its storage with others takes the lock there as well.
	 *
	 * @throws IOException if the range can't be locked, e.g. an IOExceptionWithStatus with LOCK_NOT_GRANTED
	 */
	default void lock(long offset, long length, boolean exclusive) throws IOException {
		// nothing to do for a backend that is the only one to access its storage
	}

	/** Counterpart of {@link #lock}, called when the server releases the range. */
	default void unlock(long offset, long length) throws IOException {
	}
}
```

Default methods keep existing backends compiling. `IOExceptionWithStatus.Status` gains `LOCK_NOT_GRANTED` and `FILE_LOCK_CONFLICT`.

**Depends on.** Per-file state shared by all opens of a file (see "Prerequisites").

### CHANGE_NOTIFY: directory change notifications

**Why.** Without it, a Finder or Explorer window doesn't update by itself when another client changes a folder; the user has to navigate away and back. jSMB answers `STATUS_NOT_SUPPORTED` by design (`Runtime.changeNotify`), which clients accept. macOS sent a single request in the whole session and none after the refusal.

**What it takes.** Section 2.2.35 (request), 2.2.36 (response), 3.3.5.19 (processing); MS-FSCC 2.7.1 for `FILE_NOTIFY_INFORMATION`.

- The request stays pending until something changes, so this is the first command that needs asynchronous responses (see "Prerequisites"): an interim response with `STATUS_PENDING` and an `AsyncId`, the final response later, `CANCEL` to give up (`STATUS_CANCELLED`).
- A watch per directory open: `CompletionFilter` (which kinds of change), `SMB2_WATCH_TREE` (subtree or just the directory), the client's `OutputBufferLength`.
- Completion: `FILE_NOTIFY_INFORMATION` entries with action and name relative to the watched directory. Too many changes for the buffer yield `STATUS_NOTIFY_ENUM_DIR`, telling the client to list the directory again. Closing the directory completes the request with `STATUS_NOTIFY_CLEANUP`.
- Changes that happen between two requests on the same open have to be kept for the next one.

**Optional SPI.** Two sources of changes:

1. The server itself. Every `CREATE` that creates, every rename, delete, write and `SET_INFO` passes through the handlers, so the server can notify watchers of what its own clients do, with any backend.
2. The backend, for changes that bypass the server (another process writing to the same storage, a sync client). Opt-in:

```java
public interface SmbShare {

	/**
	 * Starts reporting changes that are made to the share's content other than through this SPI.
	 *
	 * @param listener receives each change with a path relative to the share root
	 * @return a handle that stops the reporting when closed, or empty if the backend can't tell
	 */
	default Optional<AutoCloseable> watch(ChangeListener listener) throws IOException {
		return Optional.empty();
	}

	interface ChangeListener {
		void changed(String path, Change change); // ADDED, REMOVED, MODIFIED, RENAMED_FROM, RENAMED_TO
	}
}
```

A backend without it still gets (1). Reporting only (1) is a common compromise, but worth a line in the README: a client can't tell that it sees only part of the changes.

**Depends on.** Asynchronous responses; a registry of all opens per share.

## Prerequisites shared by the above

- **Per-file state.** MS-SMB2 and MS-FSA keep locks, the name and the delete-pending flag on the file (`Open.File`, `Link`), where jSMB has only per-open state. It takes a key by which two opens of the same file can be told to be the same file. `FileId` is per open, and a path changes on rename. Either the server derives the key from the normalised path and maintains it across renames, or the SPI supplies one (`SmbOpen.fileKey()`, optional, default: the path).
- **A registry of opens per share.** Today opens are found through their session only (`Session.openTable`). Rename, locks and change notifications all need "every open of this file" or "every open below this directory", across sessions and connections.
- **Asynchronous responses.** Section 3.3.4.2 (interim response), 3.3.4.3 / 3.3.4.4 (final response), 3.3.5.16 (`CANCEL`), 3.3.1.2 / 3.3.4.1.2 (credits of interim responses). Needs `Connection.AsyncCommandList`, an `AsyncId` generator, response headers with `SMB2_FLAGS_ASYNC_COMMAND`, and writes to the socket from a thread other than the one that reads requests, which `TcpConnection` isn't built for yet. `CANCEL` is a no-op today for want of anything to cancel.

## Smaller gaps

Seen in the same session; each is a refusal that clients tolerate.

- `QUERY_INFO` with `InfoType` security or quota: `STATUS_NOT_SUPPORTED`. 419 requests, about one per file that gets copied.
- `SET_INFO` with `FileAllocationInformation`: `STATUS_INVALID_INFO_CLASS`. macOS uses it to preallocate before a copy.
- FSCTL `0x00140078` during mount: `STATUS_INVALID_DEVICE_REQUEST`.
