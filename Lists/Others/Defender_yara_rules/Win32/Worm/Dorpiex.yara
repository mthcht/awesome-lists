rule Worm_Win32_Dorpiex_A_197768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorpiex.A"
        threat_id = "197768"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "&client=web_messenger&__user=%s&__a=1" ascii //weight: 10
        $x_1_2 = {8b f8 85 ff 0f 84 ?? ?? 00 00 81 3f 31 52 44 4c 53 55 0f 85 ?? ?? 00 00 8b 44 24 ?? 83 f8 0c}  //weight: 1, accuracy: Low
        $x_1_3 = {81 38 31 52 44 4c 0f 85 ?? ?? 00 00 83 7d f4 ?? 73 05 e9 ?? ?? 00 00 8b 4d ?? 83 e9 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Dorpiex_B_199068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Dorpiex.B"
        threat_id = "199068"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Dorpiex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {80 3b 21 0f 85 ?? ?? 00 00 8b 85 ?? ?? ff ff 8b 95 ?? ?? ff ff 40 89 85 ?? ?? ff ff 03 c0 03 c0}  //weight: 3, accuracy: Low
        $x_2_2 = "&client=mercury&__user=%s&__a=1" ascii //weight: 2
        $x_1_3 = "select name, value from moz_cookies where host like '%.facebook.com'" ascii //weight: 1
        $x_1_4 = {7b 65 6e 64 7d 00}  //weight: 1, accuracy: High
        $x_1_5 = "\\bot\\fbs\\" ascii //weight: 1
        $x_1_6 = {54 5a 61 70 43 6f 6d 6d 75 6e 69 63 61 74 6f 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

