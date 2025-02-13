rule Trojan_Win32_Etchfro_A_2147652351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Etchfro.A"
        threat_id = "2147652351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Etchfro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 31 8a 16 32 c2 8a d0 c0 ea 04 c0 e0 04}  //weight: 1, accuracy: High
        $x_1_2 = {8a c1 c0 e8 04 c0 e1 04 0a c1 88 02 8a 4a 01 42 84 c9 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Etchfro_B_2147652352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Etchfro.B"
        threat_id = "2147652352"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Etchfro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 02 c6 01 4d 5e c6 41 01 5a 39}  //weight: 1, accuracy: High
        $x_1_2 = {ff 74 18 50 8d 7c 18 18 6a 00}  //weight: 1, accuracy: High
        $x_1_3 = {f6 ea 30 1c 37 02 c1 47 8a d8 3b 7d 0c 72 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_Etchfro_C_2147652368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Etchfro.C"
        threat_id = "2147652368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Etchfro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8a 04 0e 32 01 8a d0 c0 ea 04 c0 e0 04}  //weight: 1, accuracy: High
        $x_1_2 = {8b ce 8a d0 c0 ea 04 c0 e0 04 0a d0 88 11 8a 41 01 41 84 c0 75 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Etchfro_D_2147652369_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Etchfro.D"
        threat_id = "2147652369"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Etchfro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4c 30 50 8d 7c 30 18 51 6a 00}  //weight: 1, accuracy: High
        $x_1_2 = {c6 06 4d c6 46 01 5a 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

