rule Trojan_Win64_GOStealer_DA_2147851049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GOStealer.DA!MTB"
        threat_id = "2147851049"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GOStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "NewStealer" ascii //weight: 1
        $x_1_3 = "screenshot" ascii //weight: 1
        $x_1_4 = "GrabScreen" ascii //weight: 1
        $x_1_5 = "wallet" ascii //weight: 1
        $x_1_6 = "discord" ascii //weight: 1
        $x_1_7 = "browser" ascii //weight: 1
        $x_1_8 = "botnet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

