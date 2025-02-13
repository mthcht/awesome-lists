rule Trojan_Win32_Meshtarl_A_2147762676_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meshtarl.A"
        threat_id = "2147762676"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meshtarl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-240] 6d 00 73 00 68 00 74 00 6d 00 6c 00 [0-32] 72 00 75 00 6e 00 68 00 74 00 6d 00 6c 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 3, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 [0-32] 70 00 61 00 73 00 74 00 65 00 62 00 69 00 6e 00 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
        $x_1_4 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 2e 00 6f 00 6e 00 69 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_5 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 73 00 6f 00 63 00 61 00 74 00 [0-240] 6b 00 65 00 65 00 70 00 61 00 6c 00 69 00 76 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 74 00 6f 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = {68 00 74 00 74 00 70 00 [0-240] 2e 00 70 00 77 00 2f 00 77 00 69 00 6e 00 [0-64] 68 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_8 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-240] 63 00 68 00 72 00 6f 00 6d 00 65 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meshtarl_C_2147762677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meshtarl.C"
        threat_id = "2147762677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meshtarl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_3_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 2e 00 65 00 78 00 65 00 [0-240] 6d 00 73 00 68 00 74 00 6d 00 6c 00 [0-32] 72 00 75 00 6e 00 68 00 74 00 6d 00 6c 00 61 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 3, accuracy: Low
        $x_1_3 = {73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-240] 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 [0-240] 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 [0-240] 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_4 = {73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-240] 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 [0-240] 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 [0-240] 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-240] 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 [0-240] 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 [0-240] 69 00 6e 00 76 00 6f 00 6b 00 65 00 2d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meshtarl_D_2147762678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meshtarl.D"
        threat_id = "2147762678"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meshtarl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-80] 2e 00 68 00 74 00 61 00 [0-64] 75 00 61 00 63 00}  //weight: 1, accuracy: Low
        $x_1_3 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-240] 68 00 74 00 74 00 70 00 [0-240] 69 00 65 00 78 00}  //weight: 1, accuracy: Low
        $x_1_4 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-240] 68 00 74 00 74 00 70 00 [0-240] 73 00 74 00 61 00 72 00 74 00 2d 00 70 00 72 00 6f 00 63 00 65 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_5 = {76 00 62 00 73 00 63 00 72 00 69 00 70 00 74 00 3a 00 [0-240] 70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-240] 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 6e 00 65 00 74 00 [0-240] 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 [0-240] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Meshtarl_B_2147763034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Meshtarl.B"
        threat_id = "2147763034"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Meshtarl"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {6d 00 73 00 68 00 74 00 61 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 3, accuracy: High
        $x_1_2 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-240] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-240] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
        $x_1_4 = {66 00 74 00 70 00 3a 00 2f 00 2f 00 [0-240] 2e 00 68 00 74 00 61 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

