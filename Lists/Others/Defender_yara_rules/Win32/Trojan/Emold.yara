rule Trojan_Win32_Emold_A_2147609402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emold.gen!A"
        threat_id = "2147609402"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emold"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {31 6f 61 64 4c 69 62 72 61 72 79 41 00}  //weight: 1, accuracy: High
        $x_1_2 = {4e 4f 54 45 50 41 44 2e 45 58 45 00 45 6e 74 65 72 20 74 65 78 74 20 68 65 72 65 2e 2e 2e 00 53 65 74 20 54 65 78 74 2e 00}  //weight: 1, accuracy: High
        $x_1_3 = {45 6e 74 65 72 20 74 65 78 74 20 68 65 72 65 2e 2e 2e 00 4e 4f 54 45 50 41 44 2e 45 58 45 00 53 65 74 20 54 65 78 74 2e 00}  //weight: 1, accuracy: High
        $x_2_4 = {57 4e 44 43 4c 41 53 53 58 45 4d 4f 54 49 4f 4e 53 00}  //weight: 2, accuracy: High
        $x_2_5 = {57 4e 44 43 4c 41 53 53 58 45 4d 4f 52 45 53 00}  //weight: 2, accuracy: High
        $x_2_6 = "/ld.php?v=1&" ascii //weight: 2
        $x_1_7 = {77 69 6e 73 74 61 30 5c 64 65 66 61 75 6c 74 00}  //weight: 1, accuracy: High
        $x_2_8 = {57 4e 44 43 4c 41 53 53 58 46 49 4e 44 45 52 58 58 00}  //weight: 2, accuracy: High
        $x_1_9 = "Content-Disposition: form-data; name=\"Upload\"" ascii //weight: 1
        $x_1_10 = {5c 65 6d 61 69 6c 73 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {75 70 6c 64 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_3_12 = {28 07 30 07 47 e2 f9 eb 0a 00 bf ?? ?? ?? ?? b9 ?? ?? 00 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Emold_B_2147610568_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emold.gen!B"
        threat_id = "2147610568"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emold"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {47 65 74 43 75 72 72 65 6e 74 54 68 72 65 61 64 00 31 6f 61 64 4c 69 62 72 61 72 79 41 00 6e 74 64 6c 6c 2e 64 6c 6c}  //weight: 2, accuracy: High
        $x_2_2 = {e9 0b 01 00 00 45 6e 74 65 72 20 74 65 78 74 20 68 65 72 65 ?? ?? ?? ?? 4e 4f 54 45 50 41 44 2e 45 58 45 00 53 65 74 20 54 65 78 74}  //weight: 2, accuracy: Low
        $x_4_3 = {28 07 30 07 47 e2 f9 eb 0a 00 bf ?? ?? ?? ?? b9 ?? ?? 00 00}  //weight: 4, accuracy: Low
        $x_2_4 = {ab a1 ab a6 95 8d 9e 9b 85 8c 8c 75 70 86 9b 6f 70 86 8c 6f 6e ab 75 86 9e ab 75 8c 88 71 7b 75 8b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Emold_C_2147610709_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Emold.gen!C"
        threat_id = "2147610709"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Emold"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 3f 4d 5a 75 ?? 8b 47 3c 89 fe 01 c7 66 81 3f 50 45 75 ?? 89 f0}  //weight: 1, accuracy: Low
        $x_1_2 = {00 31 6f 61 64 4c 69 62 72 61 72 79 41 00}  //weight: 1, accuracy: High
        $x_2_3 = {28 07 30 07 47 e2 f9 eb 0a 00 bf ?? ?? ?? ?? b9 ?? ?? 00 00}  //weight: 2, accuracy: Low
        $x_2_4 = {6a 00 6a 00 ff 15 ?? ?? 40 00 31 c0 5f 5e 5b c9 c2 10 00 ff 15 ?? ?? 40 00 89 c3 b8 ?? ?? 00 00 28 d8 b9 ?? ?? 40 00 29 d9 ff e1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

