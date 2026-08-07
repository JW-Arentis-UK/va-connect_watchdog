# Neousys WDT_DIO test bundle

This directory contains the vendor WDT_DIO 2.4.1.0 archive supplied for controlled
POC-451VTC testing.

- Archive: `WDT_DIO_202505_v2-4-1-0_Linux.zip`
- SHA256: `e78018ea9c45c4bcc6ad5a3a1c42dfe092e126093d267eecacfbe7f1e8d2f658`
- Scope: attended test systems only

The installer verifies the hash, builds the kernel module for the running kernel,
and does not start the hardware timer unless `--activate` is explicitly supplied.
Do not redistribute or deploy this proprietary vendor package to production until
its licence and platform support have been confirmed with Neousys.
