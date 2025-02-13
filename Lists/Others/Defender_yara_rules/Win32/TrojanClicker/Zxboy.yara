rule TrojanClicker_Win32_Zxboy_17731_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Zxboy"
        threat_id = "17731"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Zxboy"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\" target=_blank" ascii //weight: 1
        $x_2_2 = "%s\\update.ini" ascii //weight: 2
        $x_3_3 = "\\system32\\sysads.ini" ascii //weight: 3
        $x_3_4 = "http://ads.8866.org/" ascii //weight: 3
        $x_2_5 = "sysads.gif" ascii //weight: 2
        $x_2_6 = "update.gif" ascii //weight: 2
        $x_2_7 = "update.jpg" ascii //weight: 2
        $x_2_8 = "update.exe" ascii //weight: 2
        $x_5_9 = "http://www.zxboy.com#http://" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 5 of ($x_2_*))) or
            ((1 of ($x_5_*) and 5 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_3_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

