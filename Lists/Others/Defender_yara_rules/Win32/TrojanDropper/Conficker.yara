rule TrojanDropper_Win32_Conficker_A_2147622697_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Conficker.gen!A"
        threat_id = "2147622697"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Conficker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 1a 99 59 f7 f9 80 c2 61 88 14 1e 46 3b f7 7c e9 c6 04 3b 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 81 7d f0 d9 07}  //weight: 1, accuracy: High
        $x_1_3 = {75 15 6a 04 50 8d 85 ?? ?? ff ff 50 ff d3 eb 07}  //weight: 1, accuracy: Low
        $x_1_4 = {50 ff d7 6a 35 8d 85 18 00 35 ?? ?? ?? ?? 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Conficker_B_2147624129_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Conficker.gen!B"
        threat_id = "2147624129"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Conficker"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 7d f0 d9 07 72 12 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0f 00 c0}  //weight: 1, accuracy: Low
        $x_1_2 = {88 44 06 02 40 3d 00 01 00 00 7c f4 ff 74 24 10}  //weight: 1, accuracy: High
        $x_1_3 = {83 fe ff 0f 84 04 01 00 00 8b bd}  //weight: 1, accuracy: High
        $x_1_4 = {45 14 e7 ad a6 9c 68 ec}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

