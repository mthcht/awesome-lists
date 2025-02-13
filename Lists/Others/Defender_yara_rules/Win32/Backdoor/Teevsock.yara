rule Backdoor_Win32_Teevsock_A_2147626478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Teevsock.A"
        threat_id = "2147626478"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Teevsock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f be 08 8b 55 ?? 03 55 ?? 33 ca 8b 45 ?? 03 45 ?? 88 08 83 7d ?? 03 7e}  //weight: 1, accuracy: Low
        $x_1_2 = {68 e3 07 72 41 68 5d 52 2a 90 ff 15 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 45 fc 83 7d fc 57}  //weight: 1, accuracy: Low
        $x_1_3 = {73 71 6c 77 69 64 2e 64 6c 6c 00 00 73 76 63 68 6f 73 74 2e 65 78 65 00 73 71 6c 73 72 76 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_Win32_Teevsock_H_2147627841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Teevsock.H"
        threat_id = "2147627841"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Teevsock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "sqlsrv.exe" ascii //weight: 1
        $x_1_2 = {89 08 89 50 04 8d 84 ?? ?? ?? 00 00 8b f0 8a 08 83 c0 01 84 c9 75 f7 8d bc ?? ?? ?? 00 00 2b c6 83 c7 ff 8d a4 24 00 00 00 00 8a 4f 01}  //weight: 1, accuracy: Low
        $x_1_3 = {68 60 ea 00 00 ff 15 ?? ?? ?? 00 33 c9 33 c0 8a d1 80 c2 0d 30 90 ?? ?? ?? 00 83 f9 03 7e 04 33 c9 eb 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win32_Teevsock_J_2147628741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Teevsock.J"
        threat_id = "2147628741"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Teevsock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7d 33 8b 45 08 03 45 f0 0f be 08 8b 55 10 33 55 f8 33 ca 8b 45 08 03 45 f0 88 08 83 7d f8 04 7e 09}  //weight: 1, accuracy: High
        $x_1_2 = {42 53 2d 44 65 66 65 6e 64 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {3a 2a 3a 45 6e 61 62 6c 65 64 3a 52 41 53 53 20 53 65 72 76 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

