rule TrojanSpy_Win32_Bagopos_A_2147690057_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bagopos.A"
        threat_id = "2147690057"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagopos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 49 6e 73 74 61 6c 6c 48 6f 6f 6b 73 00 [0-5] 52 65 6d 6f 76 65 48 6f 6f 6b 73 00}  //weight: 1, accuracy: Low
        $x_1_2 = "DLLx64.dll" wide //weight: 1
        $x_1_3 = {8a 06 3c 3d 75 1a ba 01 00 00 00 8b ce e8 ?? ?? ?? ?? ba 02 00 00 00 8b ce e8 ?? ?? ?? ?? eb 3c 3c 5e 75 1d ba 01 00 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {80 f9 30 72 0d 80 f9 39 77 08 40 83 f8 14 7c ?? eb 05 83 f8 0d 7c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Bagopos_A_2147690057_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Bagopos.A"
        threat_id = "2147690057"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Bagopos"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = ":Zone.Identifier" wide //weight: 5
        $x_5_2 = "TigerVNC\\WinVNC4" wide //weight: 5
        $x_5_3 = {6c 00 73 00 6d 00 5c 00 6c 00 73 00 6d 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_5_4 = {64 00 77 00 6d 00 5c 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_5_5 = {73 00 76 00 63 00 68 00 6f 00 73 00 74 00 5c 00 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_5_6 = {52 00 75 00 6e 00 00 00 00 00 00 00 4a 00 61 00 76 00 61 00 20 00 55 00 70 00 64 00 61 00 74 00 65 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00}  //weight: 5, accuracy: High
        $x_10_7 = {26 76 3d 00 26 6d 3d 00 2b 00 00 00 63 73 3d 61 57 35 7a 5a 58 4a 30 26 70 3d 00 00 50 4f 53 54}  //weight: 10, accuracy: High
        $x_10_8 = {5c 6a 73 64 5f 31 32 2e 32 5c [0-4] 52 65 6c 65 61 73 65 5c 6a 73 64 5f 31 32 2e 32 2e 70 64 62 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

