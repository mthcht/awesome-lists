rule PWS_Win32_Kegotip_A_2147647810_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kegotip.A"
        threat_id = "2147647810"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kegotip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {25 73 3a 2a 3a 45 6e 61 62 6c 65 64 3a 4d 69 63 72 6f 73 6f 66 74 20 4f 66 66 69 63 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "SafeHeapWin32Object" ascii //weight: 1
        $x_1_3 = "\\Windows Messaging Subsystem\\MSMapiApps" ascii //weight: 1
        $x_1_4 = {4d 53 57 51 2a 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 54 75 72 62 6f 46 54 50 5c 61 64 64 72 62 6b 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "\\sites\\ws_ftp.ini" ascii //weight: 1
        $x_1_7 = "\\ipswitch\\ws_ftp" ascii //weight: 1
        $x_1_8 = "\\FileZilla\\sitemanager.xml" ascii //weight: 1
        $x_1_9 = "\\far\\plugins\\ftp\\hosts" ascii //weight: 1
        $x_1_10 = "\\ghisler\\total commander" ascii //weight: 1
        $x_1_11 = "\\GlobalSCAPE\\CuteFTP" ascii //weight: 1
        $x_1_12 = {73 6d 64 61 74 61 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_13 = {74 72 65 65 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_14 = {3c 2f 55 73 65 72 3e 00}  //weight: 1, accuracy: High
        $x_1_15 = {3c 2f 50 61 73 73 77 6f 72 64 3e 00}  //weight: 1, accuracy: High
        $x_1_16 = {3c 2f 48 6f 73 74 3e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (12 of ($x*))
}

rule PWS_Win32_Kegotip_C_2147661122_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kegotip.C"
        threat_id = "2147661122"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kegotip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 4d 53 57 51 2a 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_2 = {54 75 72 62 6f 46 54 50 5c 61 64 64 72 62 6b 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {83 e2 10 74 ?? 0f be 85 ?? ?? ff ff 83 f8 2e 75 22 0f be 8d ?? ?? ff ff 85 c9 74 ?? 0f be 95 ?? ?? ff ff 83 fa 2e 75 0b 0f be 85 ?? ?? ff ff 85 c0 74 ?? 68 04 01 00 00 8b 4d 08 51}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Kegotip_D_2147690308_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kegotip.D"
        threat_id = "2147690308"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kegotip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "index_get.php?key=YRHDXCF&action=ADD_FTP&id=%s&ftp_host=%s&ftp_login=%s&ftp_pass=%s" ascii //weight: 1
        $x_1_2 = {45 6e 63 72 79 70 74 5f 50 57 [0-5] 55 73 65 72 [0-5] 53 65 72 76 65 72 [0-4] 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 51 0c 39 55 fc 0f 83 d6 00 00 00 8b 45 08 8b 08 c1 e9 03 89 4d f4 8b 55 08 8b 02 33 d2 b9 08 00 00 00 f7 f1 89 55 f8 8b 45 fc 33 d2 b9 08 00 00 00 f7 f1 8b 45 08 0f b6 4c 10 10 8b 55 fc c1 ea 03 8b 45 0c 0f b6 14 02 23 ca 88 4d f3 8b 45 fc 33 d2 b9 08 00 00 00 f7 f1 b9 07 00 00 00 2b ca 8a 55 f3 d2 ea 88 55 f3 8b 45 08 8b 50 08 b8 07 00 00 00 2b 45 f8 0f be c8 b8 01 00 00 00 d3 e0 0f b6 c8 f7 d1 8b 45 f4 0f b6 14 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Kegotip_D_2147690946_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Kegotip.D!!Kegotip.gen!A"
        threat_id = "2147690946"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Kegotip"
        severity = "Critical"
        info = "Kegotip: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "index_get.php?key=YRHDXCF&action=ADD_FTP&id=%s&ftp_host=%s&ftp_login=%s&ftp_pass=%s" ascii //weight: 1
        $x_1_2 = {45 6e 63 72 79 70 74 5f 50 57 [0-5] 55 73 65 72 [0-5] 53 65 72 76 65 72 [0-4] 50 61 73 73 77 6f 72 64}  //weight: 1, accuracy: Low
        $x_1_3 = {0f b6 51 0c 39 55 fc 0f 83 d6 00 00 00 8b 45 08 8b 08 c1 e9 03 89 4d f4 8b 55 08 8b 02 33 d2 b9 08 00 00 00 f7 f1 89 55 f8 8b 45 fc 33 d2 b9 08 00 00 00 f7 f1 8b 45 08 0f b6 4c 10 10 8b 55 fc c1 ea 03 8b 45 0c 0f b6 14 02 23 ca 88 4d f3 8b 45 fc 33 d2 b9 08 00 00 00 f7 f1 b9 07 00 00 00 2b ca 8a 55 f3 d2 ea 88 55 f3 8b 45 08 8b 50 08 b8 07 00 00 00 2b 45 f8 0f be c8 b8 01 00 00 00 d3 e0 0f b6 c8 f7 d1 8b 45 f4 0f b6 14 02}  //weight: 1, accuracy: High
        $x_1_4 = {00 4d 53 57 51 2a 2e 74 6d 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {54 75 72 62 6f 46 54 50 5c 61 64 64 72 62 6b 2e 64 61 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

