package org.cryptomator.jsmb.smb2;

import org.cryptomator.jsmb.share.SmbShare;

/**
 * Server-side state for an active tree connect, held in {@code Session.treeConnectTable}.
 * Allocated by {@code TREE_CONNECT} (M4), retired by {@code TREE_DISCONNECT}.
 *
 * @param treeId        32-bit identifier echoed in every subsequent request's {@code TreeId} header field
 * @param shareName     the registered share name the client tree-connected to
 * @param share         the embedder-provided backend behind the share
 * @param maximalAccess NT access mask the client is granted on this tree (returned in the TREE_CONNECT response)
 * @see <a href="https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/9b0d42e9-a9ca-4d2b-9b7a-b1a12b7b6bd2">MS-SMB2 3.3.1.9 Per Tree Connect</a>
 */
public record TreeConnect(int treeId, String shareName, SmbShare share, int maximalAccess) {}
