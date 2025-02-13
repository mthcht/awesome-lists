rule TrojanClicker_Win32_Yeeha_A_2147633652_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Yeeha.A"
        threat_id = "2147633652"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Yeeha"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {62 00 61 00 69 00 64 00 75 00 2e 00 63 00 6f 00 6d [0-48] 63 6c 69 63 6b [0-48] 48 69 74 65 6d}  //weight: 10, accuracy: Low
        $x_10_2 = "OnGetPassword" ascii //weight: 10
        $x_1_3 = "getxy.asp?u=" ascii //weight: 1
        $x_1_4 = "target=\"_parent\">1</a>" ascii //weight: 1
        $x_1_5 = "geturlip.asp?go=" ascii //weight: 1
        $x_1_6 = "getno.asp?go=" ascii //weight: 1
        $x_1_7 = "geturl.asp?u=" ascii //weight: 1
        $x_1_8 = "getno.asp?u=" ascii //weight: 1
        $x_10_9 = "http://wpa.qq.com" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

