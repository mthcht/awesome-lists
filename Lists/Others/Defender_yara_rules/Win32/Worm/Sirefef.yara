rule Worm_Win32_Sirefef_A_143930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sirefef.gen!A"
        threat_id = "143930"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 31 10 40 40 49 75 f3 b8 8c 56 90 7c}  //weight: 1, accuracy: High
        $x_1_2 = {74 08 8b 40 04 85 c0 75 f1 c3 85 f6 74 05 8b 48 10 08 00 eb 0b 81 38}  //weight: 1, accuracy: Low
        $x_1_3 = {81 38 04 00 00 80 75 24 8b 40 0c 3b 05 ?? ?? ?? ?? 75 19 8b 41 04 c7 80 b8 00 00 00}  //weight: 1, accuracy: Low
        $x_2_4 = {0f 8c f1 00 00 00 8d 85 80 fc ff ff 50 ff 75 ec c7 85 80 fc ff ff 01 00 01 00 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Sirefef_A_143930_1
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Sirefef.gen!A"
        threat_id = "143930"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Sirefef"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 31 10 40 40 49 75 f3 b8 8c 56 90 7c}  //weight: 1, accuracy: High
        $x_1_2 = {74 08 8b 40 04 85 c0 75 f1 c3 85 f6 74 05 8b 48 10 08 00 eb 0b 81 38}  //weight: 1, accuracy: Low
        $x_1_3 = {81 38 04 00 00 80 75 24 8b 40 0c 3b 05 ?? ?? ?? ?? 75 19 8b 41 04 c7 80 b8 00 00 00}  //weight: 1, accuracy: Low
        $x_2_4 = {0f 8c f1 00 00 00 8d 85 80 fc ff ff 50 ff 75 ec c7 85 80 fc ff ff 01 00 01 00 ff 15}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

