rule Trojan_Win64_GoStealer_DB_2147899516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GoStealer.DB!MTB"
        threat_id = "2147899516"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GoStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID:" ascii //weight: 1
        $x_1_2 = "GoStealer" ascii //weight: 1
        $x_1_3 = "botnet" ascii //weight: 1
        $x_1_4 = "telegram-bot-api" ascii //weight: 1
        $x_1_5 = "_cgo_dummy_export" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

