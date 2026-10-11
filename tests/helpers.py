import os


def write(root, rel, text, mode=0o644):
    p = os.path.join(root, rel.lstrip("/"))
    os.makedirs(os.path.dirname(p), exist_ok=True)
    with open(p, "w") as fh:
        fh.write(text)
    os.chmod(p, mode)


def bad_root(root):
    """A fake filesystem root full of problems (never touches the real system)."""
    write(root, "/etc/passwd", "root:x:0:0::/root:/bin/bash\nhax:x:0:0::/:/bin/sh\nbob:x:1000:1000::/h:/bin/bash\n")
    write(root, "/etc/shadow", "root:!:1:0:99999:7:::\nbob:$1$abc$xyz:1:0:99999:7:::\nnopw::1:0:99999:7:::\n", 0o644)
    write(root, "/etc/ssh/sshd_config", "PermitRootLogin yes\nPermitEmptyPasswords no\nMatch User x\nPermitEmptyPasswords yes\n")
