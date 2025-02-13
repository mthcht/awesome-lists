rule Trojan_Win32_Dahrwam_A_2147599326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dahrwam.A"
        threat_id = "2147599326"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dahrwam"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "301"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "e:\\work\\malwar\\hard\\EngineDll\\release\\EngineDll.pdb" ascii //weight: 100
        $x_100_2 = "COMRPCMutex0" ascii //weight: 100
        $x_100_3 = {55 8b ec 83 ec 10 56 57 be ?? ?? ?? ?? 8d 7d f0 a5 a5 6a 0c 8d 45 f0 50 a5 6a 75 58 a4 e8 ?? ?? ?? ?? 59 59 8d 45 f0 50 6a 01 6a 00 ff 15 ?? ?? ?? ?? 8b f0 85 f6 74 13 e8 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 56 ff 15 ?? ?? ?? ?? 5f 33 c0 5e c9 c2 04 00}  //weight: 100, accuracy: Low
        $x_1_4 = "http://81.95.144.242/tes/cout.php" ascii //weight: 1
        $x_1_5 = "/rpc/cl.php" ascii //weight: 1
        $x_1_6 = "geWeb2 Agent 1.0" ascii //weight: 1
        $x_1_7 = "\\\\.\\kcp" ascii //weight: 1
        $x_1_8 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65 00 73 76 63 68 6f 73 74 00 00 73 76 63 68 6f 73 74}  //weight: 1, accuracy: High
        $x_1_9 = {45 6e 67 69 6e 65 44 6c 6c 2e 64 6c 6c 00 57 61 69 74 46 6f 72 45 78 69 74}  //weight: 1, accuracy: High
        $x_1_10 = "mxs.mail.ru" ascii //weight: 1
        $x_1_11 = "gmail-smtp-in.l.google.com" ascii //weight: 1
        $x_1_12 = "gsmtp183.google.com" ascii //weight: 1
        $x_1_13 = "in1.smtp.messagingengine.com" ascii //weight: 1
        $x_1_14 = "mail7.digitalwaves.co.nz" ascii //weight: 1
        $x_3_15 = {33 db 53 66 89 45 f0 6a 08 8d 45 ec 50 ff 75 08 66 c7 45 ec 0b 01 66 89 5d f2 e8 ?? ?? ?? ?? 83 f8 08 74 08 83 c8 ff e9 c8 00 00 00 53 6a 02 8d 45 f8 50 ff 75 08 e8 ?? ?? ?? ?? 83 f8 02 75 e4 66 81 7d f8 0b 01 75 dc 53 50 8d 45 fc 50 ff 75 08 e8 ?? ?? ?? ?? 83 f8 02 75 c9 f6 45 fc 80 74 11 53 6a 06 57 ff 75 08 e8 ?? ?? ?? ?? 83 f8 06 75 b2 f6 45 fc 40 6a 04 5f 74 0f 53 57 56 ff 75 08 e8 ?? ?? ?? ?? 3b c7 75 9a f6 45 fc 01 74 54 53 57 8d 45 f4 50 ff 75 08 e8 ?? ?? ?? ?? 3b c7 75 82 57 68 00 10 00 00 ff 75 f4 53}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_100_*) and 1 of ($x_1_*))) or
            ((3 of ($x_100_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

