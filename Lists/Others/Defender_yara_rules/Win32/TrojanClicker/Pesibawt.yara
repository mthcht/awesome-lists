rule TrojanClicker_Win32_Pesibawt_A_2147625531_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Pesibawt.A"
        threat_id = "2147625531"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Pesibawt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "/pbpro/stats/cnt.php?type=%s&said=%s&ver=%s" ascii //weight: 3
        $x_3_2 = "&#xa0;<script>function" wide //weight: 3
        $x_2_3 = "PpcBotPro" ascii //weight: 2
        $x_1_4 = "DailySearches" ascii //weight: 1
        $x_1_5 = "DailyClicks" ascii //weight: 1
        $x_1_6 = "c_search" ascii //weight: 1
        $x_1_7 = "c_click" ascii //weight: 1
        $x_1_8 = "MyWebDocument" wide //weight: 1
        $x_1_9 = "MyWebBrowserHost" wide //weight: 1
        $x_1_10 = "&q={KEYWORD}&btnG" ascii //weight: 1
        $x_1_11 = "&q={KEYWORD}&lr=" ascii //weight: 1
        $x_1_12 = "&q={KEYWORD}&spell" ascii //weight: 1
        $x_1_13 = "&q={KEYWORD}&start" ascii //weight: 1
        $x_1_14 = "&q={KEYWORD}||click.php" ascii //weight: 1
        $x_1_15 = "&q={KEYWORD}||go.php" ascii //weight: 1
        $x_1_16 = "?p={KEYWORD}&ei" ascii //weight: 1
        $x_1_17 = "?q={KEYWORD}&first" ascii //weight: 1
        $x_1_18 = "?q={KEYWORD}&FORM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((14 of ($x_1_*))) or
            ((1 of ($x_2_*) and 12 of ($x_1_*))) or
            ((1 of ($x_3_*) and 11 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 9 of ($x_1_*))) or
            ((2 of ($x_3_*) and 8 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

