rule Trojan_Win64_TitanStealer_DA_2147839670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TitanStealer.DA!MTB"
        threat_id = "2147839670"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TitanStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "stealer_v" ascii //weight: 1
        $x_1_3 = "screenshot.CaptureScreen" ascii //weight: 1
        $x_1_4 = "ChromeCommonCookie" ascii //weight: 1
        $x_1_5 = "grabfile" ascii //weight: 1
        $x_1_6 = "antidebug" ascii //weight: 1
        $x_1_7 = "antivm" ascii //weight: 1
        $x_1_8 = "time.Sleep" ascii //weight: 1
        $x_1_9 = "master secret" ascii //weight: 1
        $x_1_10 = "sendlog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

