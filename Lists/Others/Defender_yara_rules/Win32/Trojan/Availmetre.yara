rule Trojan_Win32_Availmetre_A_2147634141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Availmetre.A"
        threat_id = "2147634141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Availmetre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 73 2e 44 4c 4c 00 48 6f 6f 6b 73}  //weight: 5, accuracy: High
        $x_2_2 = {c7 45 c8 53 4f 46 54 c7 45 cc 57 41 52 45 c7 45 d0 5c 4d 69 63 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? c7 45 e8 6e 74 56 65 c7 45 ec 72 73 69 6f c7 45 f0 6e 5c 52 75 c6 45 f4 6e}  //weight: 2, accuracy: Low
        $x_1_3 = {43 61 6c 6c 57 69 6e 64 6f 77 50 72 6f 63 41 [0-6] 43 72 65 61 74 65 44 69 61 6c 6f 67 50 61 72 61 6d 57 [0-6] 53 65 74 57 69 6e 64 6f 77 4c 6f 6e 67 41}  //weight: 1, accuracy: Low
        $x_1_4 = "U; Windows NT 5.1; ru; rv:1.9.0.11) Gecko/2009060215 Firefox/3.0.11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Availmetre_B_2147634142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Availmetre.B"
        threat_id = "2147634142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Availmetre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {74 62 2e 44 4c 4c 00 62 6f 74 6b 6f 6d 61 6e 64}  //weight: 5, accuracy: High
        $x_1_2 = {66 c7 45 e4 45 00 66 c7 45 e6 58 00 66 c7 45 e8 50 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 66 c7 45 f4 2e 00 66 c7 45 f6 45 00 66 c7 45 f8 58 00 66 c7 45 fa 45 00}  //weight: 1, accuracy: Low
        $x_1_3 = {62 6f 74 00 65 78 65 63 00 65 78 69 74 64 6c 6c 00 70 6f 77 65 72 00 78 61 6e 61 00 73 68 65 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Availmetre_B_2147634142_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Availmetre.B"
        threat_id = "2147634142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Availmetre"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {54 53 2e 64 6c 6c [0-6] 41 64 64 50 72 6f 63 65 73 73 45 78 63 6c 75 73 69 6f 6e [0-6] 47 65 74 43 68 61 6e 67 65 52 65 63 74 [0-6] 47 65 74 43 68 61 6e 67 65 64 57 69 6e 64 6f 77 4c 69 73 74}  //weight: 5, accuracy: Low
        $x_1_2 = {54 56 2e 44 4c 4c [0-6] 41 64 64 50 72 6f 63 65 73 73 45 78 63 6c 75 73 69 6f 6e [0-6] 47 65 74 43 68 61 6e 67 65 52 65 63 74 [0-6] 47 65 74 43 68 61 6e 67 65 64 57 69 6e 64 6f 77 4c 69 73 74}  //weight: 1, accuracy: Low
        $x_1_3 = "U; Windows NT 5.1; ru; rv:1.9.0.11) Gecko/2009060215 Firefox/3.0.11" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

