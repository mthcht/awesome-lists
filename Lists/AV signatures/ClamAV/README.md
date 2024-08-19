You can download the ClamAV signature databases directly from their update servers:
- Official Database: https://database.clamav.net/main.cvd
- Daily Updates: https://database.clamav.net/daily.cvd
- Bytecode Database: https://database.clamav.net/bytecode.cvd

These .cvd files are compressed, and you can extract them using the sigtool utility, which is part of ClamAV.

Signatures Extraction on windows:
```
\clamav> .\clamav-1.4.0.win.x64\sigtool.exe --unpack .\main.cvd
\clamav> .\clamav-1.4.0.win.x64\sigtool.exe --unpack .\daily.cvd
```

This will extract the .ndb, .hdb, .ldb, etc., files containing the actual signatures.


- *.ndb (e.g., daily.ndb, main.ndb)
  - These files contain standard signature definitions for ClamAV. They often include signatures for known malware in a simple text format.
  - Structure: Each line in the .ndb file contains a signature name, target file type, offset, and the signature's hexadecimal pattern.

- *.hdb (e.g., daily.hdb, main.hdb)
  - These files contain MD5-based hash signatures. They are typically used for file-based malware detection via hash matching.
  - Structure: Each line has the hash, file size, and signature name.

- *.ldb (e.g., daily.ldb, main.ldb)
  - These files contain logical signature definitions. These are more complex than simple hash or pattern-based signatures and can detect specific sequences of data.
  - Structure: Each line defines a logical signature that may involve conditions or sequences of bytes.

- *.mdb (e.g., daily.mdb, main.mdb)
  - These files contain malware detection signatures that are byte sequences used by ClamAV for scanning. They are typically related to specific malware strains.
  - Structure: Byte sequences with conditions on file properties.

- *.fp (e.g., daily.fp, main.fp)
  - These are false-positive exclusion lists. These files help ClamAV avoid flagging legitimate files as malicious.
  - Structure: Similar to other signature files but excludes specific hash signatures known to be false positives.

- *.info (e.g., daily.info, main.info)
  - These files contain metadata about the signature databases themselves, including version information and database size. These are useful for tracking the updates and versions of the signature databases.
