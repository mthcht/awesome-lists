rule TrojanDropper_Win32_Dogkild_A_2147627331_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dogkild.A"
        threat_id = "2147627331"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 64 72 69 76 65 72 73 5c 67 6d 2e 64 6c 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "cmd /c taskkill /im egui.exe /f" ascii //weight: 1
        $x_1_3 = "cacls %s /e /p everyone:f" ascii //weight: 1
        $x_1_4 = "rundll32.exe %s, droqp" ascii //weight: 1
        $x_2_5 = {66 81 7c 24 10 d7 07 76}  //weight: 2, accuracy: High
        $x_2_6 = {66 81 7d e0 d7 07 0f 86}  //weight: 2, accuracy: High
        $x_2_7 = {76 2a 8b 45 fc 53 8a 04 07 fe c0 88 45 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_Dogkild_B_2147627447_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Dogkild.B"
        threat_id = "2147627447"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 64 72 69 76 65 72 73 5c 67 6d 2e 64 6c 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {5c 5c 2e 5c 70 63 69 64 75 6d 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {63 6d 64 20 2f 63 20 6e 65 74 20 73 74 6f 70 20 77 73 63 73 76 63 00}  //weight: 1, accuracy: High
        $x_2_4 = {83 c4 14 56 ff d3 83 f8 02 74 08 56 ff d3 83 f8 03 d1 6c 24 ?? 47 83 ff 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

