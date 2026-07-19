# checkdisk

A self-contained, pure-Python NTFS repair tool — the parts of `chkdsk /f` that matter for a crashed volume (dangling dirents, torn indexes, 
lost files, torn truncates, `$Bitmap`, `$Secure`, the USN journal). 

`checkdisk` uses a native read/write engine that parses and rewrites on-disk NTFS structures directly, with multi-sector fixups and plan-then-commit 
atomicity. 

## Install

```
pip install checkdisk
```

Or download `checkdisk.py` and run via `python checkdisk.py xx` 

## Quick start

`checkdisk` works on the raw (unmounted) device or an image file — never through
a mount:

```sh
checkdisk list                        # find NTFS partitions (mounts nothing)
sudo umount /mnt/point                # get off the volume first
sudo setfacl -m u:$USER:rw /dev/sdXN  # or run the tool with sudo
checkdisk /f /dev/sdXN                # dry run: reports, writes nothing
checkdisk /f /dev/sdXN --really       # repair (each fix re-verified)
checkdisk /f /dev/sdXN                # confirm: expect 0 remaining
```

`/r` adds the full surface read. Running from the repo instead:
`python checkdisk.py /f ...` — identical.
