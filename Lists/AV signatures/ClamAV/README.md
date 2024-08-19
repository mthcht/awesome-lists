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
