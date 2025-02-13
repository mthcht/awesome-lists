rule Worm_Win32_Hokobot_A_2147693379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hokobot.A!dha"
        threat_id = "2147693379"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hokobot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "==gKg5XI+BmK=cVauR2b3NHIIVGbwByUlJndpNWZ" ascii //weight: 10
        $x_10_2 = "SetWinHoK" ascii //weight: 10
        $x_10_3 = "[autorun]" ascii //weight: 10
        $x_10_4 = "DLD-S:" ascii //weight: 10
        $x_10_5 = "DLD-E:" ascii //weight: 10
        $x_10_6 = "\\%s-%i.%i.%i.%i.%i.%i.sys" ascii //weight: 10
        $x_1_7 = ":\\autorun.exe" ascii //weight: 1
        $x_1_8 = "##Data##: Active Window-->" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_10_*) and 2 of ($x_1_*))) or
            ((6 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Hokobot_B_2147696563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Hokobot.B!dha"
        threat_id = "2147696563"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Hokobot"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XXXTomato=" ascii //weight: 1
        $x_1_2 = {76 69 6d 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {2f 77 69 70 2f 69 6e 64 65 78 2e 70 68 70 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 00 72 00 72 00 6f 00 72 00 2e 00 72 00 65 00 6e 00 61 00 6d 00 65 00 66 00 69 00 6c 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_5_5 = "[autorun]" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

