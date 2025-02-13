rule Spammer_Win32_Newacc_A_2147601259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Newacc.A"
        threat_id = "2147601259"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Newacc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {53 8b d9 8b 53 18 83 fa 10 56 57 72 05 8b 43 04 eb 03 8d 43 04 8b 74 24 10 3b f0 72 34 83 fa 10 8d 43 04 72 04 8b 08 eb 02 8b c8 8b 7b 14 03 f9 3b fe 76 1d 83 fa 10 72 02 8b 00 8b 4c 24 14 51 2b f0 56 53 8b cb e8 ?? ?? ff ff 5f 5e 5b c2 08 00}  //weight: 10, accuracy: Low
        $x_10_2 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c [0-8] 5c 76 61 72 73 00}  //weight: 10, accuracy: Low
        $x_10_3 = {53 6f 66 74 77 61 72 65 5c 4d 69 63 72 6f 73 6f 66 74 5c [0-8] 20 44 61 74 61 00}  //weight: 10, accuracy: Low
        $x_10_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_5 = "InternetOpenUrlA" ascii //weight: 10
        $x_10_6 = {68 74 74 70 3a 2f 2f ?? ?? 2e 6f 63 72 73 65 72 76 69 63 65 2e 62 69 7a 2f}  //weight: 10, accuracy: Low
        $x_5_7 = {4e 6f 52 65 6d 6f 76 65 [0-4] 46 6f 72 63 65 52 65 6d 6f 76 65}  //weight: 5, accuracy: Low
        $x_5_8 = {72 75 6e 00 5c 77 69 6e 2e 69 6e 69 00 00 00 00 57 69 6e 64 6f 77 73 00 6c 6f 61 64 00 00 00 00 5c 73 79 73 74 65 6d 2e 69 6e 69}  //weight: 5, accuracy: High
        $x_5_9 = "window.google" ascii //weight: 5
        $x_5_10 = "lamodano.info" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 4 of ($x_5_*))) or
            ((4 of ($x_10_*) and 2 of ($x_5_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Spammer_Win32_Newacc_A_2147605730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Newacc.gen!A"
        threat_id = "2147605730"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Newacc"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {6a 0d 53 68 ?? ?? ?? 00 8b ce 89 5c 24 78 e8 ?? ?? ff ff 83 f8 ff 0f 84 ?? ?? 00 00 55 57 8d 9b 00 00 00 00 6a 06 83 c0 0d 50}  //weight: 4, accuracy: Low
        $x_4_2 = {72 0d 8b 4c 24 14 51 e8 ?? ?? 00 00 83 c4 04 6a 08 68 ?? ?? ?? 00 8d 4c 24 ?? 89 74 24 ?? 89 5c 24 ?? 88 5c 24 ?? e8 ?? ?? ff ff 6a 01 68 ?? ?? ?? 00 8d 4c 24 18}  //weight: 4, accuracy: Low
        $x_1_3 = {2f 70 6f 73 74 5f 61 63 63 2e 63 67 69 3f 6c 3d 00}  //weight: 1, accuracy: High
        $x_1_4 = {2f 67 65 6e 5f 6e 61 6d 65 2e 63 67 69 00}  //weight: 1, accuracy: High
        $x_1_5 = {6d 6f 72 65 61 63 6f 76 00}  //weight: 1, accuracy: High
        $x_1_6 = {2f 72 65 67 2e 73 72 66 00}  //weight: 1, accuracy: High
        $x_1_7 = {2f 6f 63 72 2f 00 00 00 70 69 63 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 70 66 66 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

