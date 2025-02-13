rule TrojanClicker_Win32_Baffec_A_2147655478_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Baffec.A"
        threat_id = "2147655478"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Baffec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--silent" wide //weight: 1
        $x_1_2 = "/click.php?ver=%s&type=%s" wide //weight: 1
        $x_1_3 = "TimerReportTimer" ascii //weight: 1
        $x_1_4 = "MEDIA_SEARCH_CLOSE_MESSAGE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

