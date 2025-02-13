rule Backdoor_Win32_Buminpom_A_2147640962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Buminpom.A"
        threat_id = "2147640962"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Buminpom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_20_1 = "mac_addr=%s" wide //weight: 20
        $x_1_2 = "//AppDownURL" wide //weight: 1
        $x_1_3 = "//CacheDelete" wide //weight: 1
        $x_1_4 = "//CmdServer" wide //weight: 1
        $x_1_5 = "//CmdUpdateTime" wide //weight: 1
        $x_1_6 = "//CntWindow" wide //weight: 1
        $x_1_7 = "//CookieDomain" wide //weight: 1
        $x_1_8 = "//JSExec" wide //weight: 1
        $x_1_9 = "//UpdateURL" wide //weight: 1
        $x_1_10 = "//WaitTime" wide //weight: 1
        $x_1_11 = "//delayWindow" wide //weight: 1
        $x_1_12 = "//fileDown" wide //weight: 1
        $x_1_13 = "//ifJSRUN" wide //weight: 1
        $x_1_14 = "//ifRandom" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

