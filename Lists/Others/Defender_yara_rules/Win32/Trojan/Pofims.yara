rule Trojan_Win32_Pofims_A_2147709874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pofims.A!!Pofims.gen!dha"
        threat_id = "2147709874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pofims"
        severity = "Critical"
        info = "Pofims: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 41 18 50 e8 7b 00 00 00 83 c4 08 5d c2 04 00 c3 cc cc cc cc cc cc cc cc cc cc cc cc cc cc 55 8b ec 53 56 57 55 6a 00 6a 00 68 58 24 3e 02 ff 75 08 e8 26 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pofims_B_2147709875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pofims.B!!Pofims.gen!dha"
        threat_id = "2147709875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pofims"
        severity = "Critical"
        info = "Pofims: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 50 6a fe 68 60 24 3e 02 64 ff 35 00 00 00 00 a1 40 60 3e 02 33 c4 50 8d 44 24 04 64 a3 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Pofims_C_2147709876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pofims.C!!Pofims.gen!dha"
        threat_id = "2147709876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pofims"
        severity = "Critical"
        info = "Pofims: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 40 85 c9 0f 4f c8 8b c1 c3 6a 00 ff 74 24 14 ff 74 24 14 ff 74 24 14 ff 74 24 14 e8 04 00 00 00 83 c4 14 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

