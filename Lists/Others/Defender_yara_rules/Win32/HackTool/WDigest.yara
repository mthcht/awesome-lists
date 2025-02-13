rule HackTool_Win32_WDigest_A_2147724202_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/WDigest.A"
        threat_id = "2147724202"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WDigest"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff d0 89 44 24 10 e9 ?? ?? ?? ?? 8b 7d 0c 8b 4f 04 39 19 0f 85 ?? ?? ?? ?? 8b 40 04 53 ff 75 10 ff 37 ff 36 ff 30 ff 15}  //weight: 2, accuracy: Low
        $x_1_2 = {89 41 04 3b c7 74 ?? 8b 06 8b 40 04 81 38 4d 44 4d 50 75 ?? b9 ?? ?? ?? ?? 66 39 48 04}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 73 61 49 c7 44 24 ?? 43 61 6e 63 c7 44 24 ?? 65 6c 4e 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {72 1c 81 79 0c ?? ?? ?? ?? 73 13 6a 0b 58 6a 24 5f 6a 1e}  //weight: 1, accuracy: Low
        $x_1_5 = {42 43 72 79 c7 45 ?? 70 74 47 65 c7 45 ?? 6e 65 72 61}  //weight: 1, accuracy: Low
        $x_1_6 = {81 7d d8 52 55 55 55 0f 85 ?? ?? 00 00 8b 45 08}  //weight: 1, accuracy: Low
        $x_1_7 = {81 7e 04 4b 53 53 4d 75 ?? 03 75 f8}  //weight: 1, accuracy: Low
        $x_1_8 = {6a 6c 58 6a 73 66 89 ?? e8 58 6a 61}  //weight: 1, accuracy: Low
        $x_1_9 = "CredentialKeys" ascii //weight: 1
        $x_1_10 = {25 00 6c 00 53 00 25 00 6c 00 53 00 25 00 6c 00 53 00 3a 00 25 00 6c 00 53 00 00 00}  //weight: 1, accuracy: High
        $x_2_11 = {77 00 64 00 69 00 67 00 65 00 73 00 74 00 2e 00 64 00 6c 00 6c 00 00 00}  //weight: 2, accuracy: High
        $x_1_12 = {6c 00 73 00 61 00 73 00 72 00 76 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

