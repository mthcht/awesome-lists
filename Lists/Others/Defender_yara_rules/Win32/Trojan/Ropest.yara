rule Trojan_Win32_Ropest_E_2147688178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ropest.E"
        threat_id = "2147688178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ropest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 c0 51 2d 9e cc c1 c0 0f 69 c0 93 35 87 1b}  //weight: 1, accuracy: High
        $x_1_2 = {41 53 54 45 52 4f 50 45 5f 43 4c 49 43 4b 45 52 5f 4d 55 54 45 58 00}  //weight: 1, accuracy: High
        $x_1_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6c 69 76 65 6a 6f 75 72 6e 61 6c 2e 63 6f 6d 2f 73 65 61 72 63 68 2f 3f 68 6f 77 3d 74 6d 26 61 72 65 61 3d 64 65 66 61 75 6c 74 26 71 3d 25 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ropest_E_2147688178_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ropest.E"
        threat_id = "2147688178"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ropest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "ASTEROPE_CLICKER_MUTEX" wide //weight: 100
        $x_100_2 = "ASTEROPE_AUTORUN_MUTEX" wide //weight: 100
        $x_100_3 = "ASTEROPE_PROTECTED_STORAGE_KEY" ascii //weight: 100
        $x_10_4 = {8a 19 88 18 88 11 0f b6 00 0f b6 ca 03 c8 81 e1 ff 00 00 00}  //weight: 10, accuracy: High
        $x_10_5 = {03 ca 0f b6 c1 8a 4c 04 ?? 32 0c 1f 88 0b 49 03 de 4d 2b de 75 c3}  //weight: 10, accuracy: Low
        $x_1_6 = {69 c0 51 2d 9e cc c1 c0 0f 69 c0 93 35 87 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            ((1 of ($x_100_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Ropest_J_2147691470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ropest.J"
        threat_id = "2147691470"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ropest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ASTEROPE" ascii //weight: 1
        $x_1_2 = {56 42 6f 78 4d 6f 75 73 65 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {77 69 6e 65 5f 67 65 74 5f 75 6e 69 78 5f 66 69 6c 65 5f 6e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8}  //weight: 1, accuracy: High
        $x_1_5 = {3d 40 1a cd 00 0f 84 3f 01 00 00 3d 08 c5 bb 6c 0f 84 34 01 00 00 3d 82 16 4e 77}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Ropest_K_2147695442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ropest.K"
        threat_id = "2147695442"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ropest"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 41 53 54 45 52 4f 50 45}  //weight: 1, accuracy: High
        $x_1_2 = {2f 65 6e 63 2f 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {c1 e8 10 33 c2 69 c0 6b ca eb 85 8b c8 c1 e9 0d 33 c8}  //weight: 1, accuracy: High
        $x_1_4 = {8a 19 88 18 88 11 0f b6 00 0f b6 ca 03 c1 25 ff 00 00 00 8a 84 ?? ?? ?? ff ff 32 04 37 88 06 46}  //weight: 1, accuracy: Low
        $x_1_5 = {0f b6 f0 83 fe 66 7f 30 74 25 83 fe 26 74 17 83 fe 2e 74 12 83 fe 36 74 0d 83 fe 3e 74 08 83 c6 9c 83 fe 01}  //weight: 1, accuracy: High
        $x_1_6 = {81 38 21 43 46 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

