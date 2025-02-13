rule TrojanSpy_Win32_Shiotob_A_2147647706_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Shiotob.A"
        threat_id = "2147647706"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Shiotob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b c0 80 fc 30 7c ?? 80 fc 39 7f ?? 80 ec 30 eb ?? 80 fc 41 7c ?? 80 fc 46 7f ?? 80 ec 41 80 c4 0a}  //weight: 2, accuracy: Low
        $x_2_2 = {6a 00 6a 02 ff 15 ?? ?? ?? ?? 8b d8 83 fb ff 74 ?? c7 85 ?? ?? ?? ?? 28 01 00 00 8d 85}  //weight: 2, accuracy: Low
        $x_2_3 = {26 6f 73 76 65 72 3d 00 26 69 70 63 6e 66 3d 00 26 73 63 6b 70 6f 72 74 3d 00 26 63 6d 6f 62 6a 3d}  //weight: 2, accuracy: High
        $x_2_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 75 73 65 72 69 6e 69 74 2e 65 78 65 00 00 44 65 62 75 67 67 65 72}  //weight: 2, accuracy: High
        $x_1_5 = "SYSTEM\\ControlSet001\\Control\\Session Manager\\AppCertDlls" ascii //weight: 1
        $x_1_6 = "-update" ascii //weight: 1
        $x_1_7 = "-autorun" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Shiotob_B_2147682887_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Shiotob.B"
        threat_id = "2147682887"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Shiotob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c0 04 81 e9 ?? ?? ?? ?? 31 08 4a 75 f2}  //weight: 1, accuracy: Low
        $x_1_2 = {88 c3 32 1c 0a c1 e8 08 33 04 9d ?? ?? ?? ?? 41 75 ee}  //weight: 1, accuracy: Low
        $x_1_3 = {8b d6 83 c2 04 88 02 c6 03 e9 47}  //weight: 1, accuracy: High
        $x_1_4 = {ba 35 bf a0 be 8b c3 e8 ?? ?? ?? ?? a3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Shiotob_C_2147690497_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Shiotob.C"
        threat_id = "2147690497"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Shiotob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Best.pdf" ascii //weight: 1
        $x_1_2 = "http://Quotie" wide //weight: 1
        $x_1_3 = "measur.Turn" wide //weight: 1
        $x_1_4 = ".Silent" wide //weight: 1
        $x_2_5 = {6a 00 6a 00 6a 01 6a 00 6a 02 68 00 00 00 40 8d 8d d8 fe ff ff 51 ff 15 ?? ?? ?? ?? 89 45 f0 8b 55 ec 83 ea 1b 81 fa d5 00 00 00 76 17 8b 45 ec 03 05 ?? ?? ?? ?? 0f b7 0d ?? ?? ?? ?? 03 c1 a3 ?? ?? ?? ?? 83 7d f0 ff 74 17 6a 01 6a 00 6a 00 8d 95 d8 fe ff ff 52 6a 00 6a 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Shiotob_D_2147726890_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Shiotob.D!bit"
        threat_id = "2147726890"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Shiotob"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-update" ascii //weight: 1
        $x_1_2 = "-autorun" ascii //weight: 1
        $x_1_3 = {26 69 70 63 6e 66 3d 00 26 73 63 6b 70 6f 72 74 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_5_5 = {88 c3 32 1c 0a c1 e8 08 33 04 9d ?? ?? ?? ?? 41 75 ee}  //weight: 5, accuracy: Low
        $x_5_6 = {83 45 fc 04 81 6d f0 ?? ?? ?? ?? 8b 45 ?? 8b 55 ?? 31 10 ff 45 ?? ff 4d ?? 75 e5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

