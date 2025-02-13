rule TrojanDropper_Win32_Insebro_A_2147800775_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Insebro.A"
        threat_id = "2147800775"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Insebro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b d8 68 8c 00 00 00 68 ?? ?? ?? ?? 53 e8 ?? ?? ff ff 68 8c 00 00 00}  //weight: 10, accuracy: Low
        $x_1_2 = "\\system32\\net.exe stop \"Security Center\"" ascii //weight: 1
        $x_1_3 = "Navigation blocked</title>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Insebro_A_2147804184_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Insebro.gen!A"
        threat_id = "2147804184"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Insebro"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 69 65 62 68 6f 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {53 6f 66 74 77 61 72 65 5c 41 70 70 44 61 74 61 4c 6f 77 5c 42 48 4f 69 6e 69 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {55 41 43 44 69 73 61 62 6c 65 4e 6f 74 69 66 79 00}  //weight: 1, accuracy: High
        $x_1_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {50 6f 6c 69 63 69 65 73 5c 53 79 73 74 65 6d 00}  //weight: 1, accuracy: High
        $x_1_6 = {45 6e 61 62 6c 65 20 42 72 6f 77 73 65 72 20 45 78 74 65 6e 73 69 6f 6e 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {49 45 42 48 4f 2e 54 49 45 41 64 76 42 48 4f 00}  //weight: 1, accuracy: High
        $x_1_8 = {c7 06 ff 00 00 00 8b 06 e8 ?? ?? ?? ?? 8b d8 56 53 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

