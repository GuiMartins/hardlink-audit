"""Translate a path as reported by a container's own API into a path this
tool can actually stat() - by walking through that container's *own* mount
table, then through this tool's host-root bind mount.

This is what lets the tool work regardless of how the deployment mounts
things: it never assumes a fixed folder layout, it reads it fresh from
Docker every run.
"""
import os


class UnresolvedPath(Exception):
    def __init__(self, container_path, mounts):
        self.container_path = container_path
        self.mounts = mounts
        super().__init__(
            f"path '{container_path}' não está coberto por nenhum mount conhecido "
            f"desse container ({[m['destination'] for m in mounts]})"
        )


class PathResolver:
    def __init__(self, mounts, host_root="/hostroot"):
        # Longest destination first so the most specific bind mount wins
        # (e.g. a container with both '/data' and '/data/torrents' mounted).
        self.mounts = sorted(mounts, key=lambda m: len(m["destination"]), reverse=True)
        self.host_root = host_root

    def to_host_path(self, container_path):
        """Real path on the Docker host, or None if unresolvable."""
        for mount in self.mounts:
            dest = mount["destination"].rstrip("/")
            if container_path == dest or container_path.startswith(dest + "/"):
                rel = container_path[len(dest):].lstrip("/")
                return os.path.normpath(os.path.join(mount["source"], rel))
        return None

    def to_local_path(self, container_path):
        """Path this tool's own process can stat(), given HOST_ROOT is bind
        mounted read-only into this container at self.host_root."""
        host_path = self.to_host_path(container_path)
        if host_path is None:
            return None
        return os.path.normpath(os.path.join(self.host_root, host_path.lstrip("/")))
