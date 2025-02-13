rule Trojan_Win32_LodaRat_RPY_2147837637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LodaRat.RPY!MTB"
        threat_id = "2147837637"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LodaRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PassW8.txt" wide //weight: 1
        $x_1_2 = "Klog.txt" wide //weight: 1
        $x_1_3 = "ip-score.com" wide //weight: 1
        $x_1_4 = "firefox.ex" wide //weight: 1
        $x_1_5 = "Googlee" wide //weight: 1
        $x_1_6 = "WScript.Sleep 5000" wide //weight: 1
        $x_1_7 = "OUHUJY.lnk" wide //weight: 1
        $x_1_8 = "stealoperaer" wide //weight: 1
        $x_1_9 = "stealchromer" wide //weight: 1
        $x_1_10 = "GETFIREFOXPASSWORD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

