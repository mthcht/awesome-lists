rule Trojan_Win32_Lamechi_A_2147626664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lamechi.A"
        threat_id = "2147626664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamechi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 45 08 47 86 c8 61 03 f9 33 c7 2b d0 ff 4d 0c 75 be}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 3f 41 4b 0f 85 ?? ?? ?? 00 56 8b 77 3c 03 f7 81 3e 50 45 00 00 0f 85 ?? ?? ?? 00 66 81 7e 14 e0 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lamechi_C_2147643499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lamechi.C"
        threat_id = "2147643499"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamechi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 aa aa aa aa 39 8c 04 ?? ?? ?? ?? 74 0a 40 3d 00 02 00 00 72 ef eb 0d 8d 96 00 08 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {c7 00 4e 56 53 2e c7 40 08 00 00 00 00 c7 40 04 05 00 00 00 c7 40 0c 00 00 00 00 c7 40 10 10 27 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lamechi_E_2147648279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lamechi.E"
        threat_id = "2147648279"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lamechi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 45 08 47 86 c8 61 03 f9 33 c7 2b d0 ff 4d 0c 75 be}  //weight: 1, accuracy: High
        $x_1_2 = {81 39 4e 64 69 73 75 6f a1 ?? ?? ?? ?? 83 78 34 00 74 64}  //weight: 1, accuracy: Low
        $x_1_3 = {81 3e 58 4a 56 32 0f 85 ?? ?? ?? ?? 39 56 0c 0f 87 ?? ?? ?? ?? f6 c2 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

