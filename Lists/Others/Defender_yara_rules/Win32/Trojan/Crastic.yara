rule Trojan_Win32_Crastic_A_2147681452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crastic.gen!A"
        threat_id = "2147681452"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crastic"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 53 50 8b 43 34 57 6a 04 68 00 20 00 00 52 50 ff 15}  //weight: 1, accuracy: High
        $x_1_2 = {63 73 72 73 73 2e 64 6c 6c 00 52 75 6e 64 6c 6c 33 32 57 00 53 65 72 76 69 63 65 4d 61 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Crastic_B_2147681453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crastic.gen!B"
        threat_id = "2147681453"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crastic"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f8 02 74 18 39 b5}  //weight: 1, accuracy: High
        $x_1_2 = {80 3c 01 5c 75 06 42 83 fa 01 77 79 40 3b c6 72 e2 83 fa 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Crastic_C_2147688029_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crastic.gen!C"
        threat_id = "2147688029"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crastic"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {ff d7 88 04 33 46 83 fe 40 72 f5 5f 8b 4d fc 33 cd 5e e8}  //weight: 1, accuracy: High
        $x_1_2 = {63 73 72 73 73 2e 64 6c 6c 00 52 75 6e 64 6c 6c 33 32 4d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Crastic_C_2147708079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crastic.C"
        threat_id = "2147708079"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crastic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {66 61 63 65 62 6f 6f 6b 2e 63 6f 6d 00 [0-16] 64 72 6f 70 62 6f 78 2e 63 6f 6d 00 [0-16] 6c 69 6e 6b 65 64 69 6e 2e 63 6f 6d 00 [0-16] 74 77 69 74 74 65 72 2e 63 6f 6d 00 [0-16] 77 69 6b 69 70 65 64 69 61 2e 6f 72 67}  //weight: 10, accuracy: Low
        $x_10_2 = {6d 61 69 6c 2e 79 61 68 6f 6f 2e 63 6f 6d 00 [0-16] 77 77 77 2e 70 61 79 70 61 6c 2e 63 6f 6d 00 [0-16] 77 77 77 2e 6e 65 74 66 6c 69 78 2e 63 6f 6d 00 [0-16] 6c 6f 67 69 6e 2e 6d 69 63 72 6f 73 6f 66 74 6f 6e 6c 69 6e 65 2e 63 6f 6d}  //weight: 10, accuracy: Low
        $x_10_3 = {00 52 75 6e 64 6c 6c 2e 64 6c 6c 00 52 75 6e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_1_4 = {8d 46 ff 85 c0 74 0a 8a 54 08 ff 30 14 08 48 75 f6}  //weight: 1, accuracy: High
        $x_1_5 = {83 c4 10 3b f8 76 0c 8a 4c 30 ff 30 0c 30 40 3b c7 72 f4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Crastic_D_2147708080_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Crastic.D"
        threat_id = "2147708080"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Crastic"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 52 75 6e 64 6c 6c 2e 64 6c 6c 00 52 75 6e 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 52 75 6e 64 6c 6c 2e 64 6c 6c 00 52 75 6e 64 6c 6c 33 32 53 00}  //weight: 10, accuracy: High
        $x_11_3 = {00 63 73 72 73 73 2e 64 6c 6c 00 52 75 6e 64 6c 6c 33 32 4d 00}  //weight: 11, accuracy: High
        $x_2_4 = {8b ff 8a 88 ?? ?? ?? ?? 30 88 ?? ?? ?? ?? 48 75 f1 33 c9 83 f8 04 37 00 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? c7 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*))) or
            ((2 of ($x_10_*))) or
            ((1 of ($x_11_*) and 1 of ($x_2_*))) or
            ((1 of ($x_11_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

