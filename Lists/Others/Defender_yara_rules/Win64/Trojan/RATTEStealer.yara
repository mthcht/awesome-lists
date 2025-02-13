rule Trojan_Win64_RATTEStealer_DA_2147900215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/RATTEStealer.DA!MTB"
        threat_id = "2147900215"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "RATTEStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RATTE/RATTEgo" ascii //weight: 1
        $x_1_2 = "gorilla/websocket" ascii //weight: 1
        $x_1_3 = "main.BotToken" ascii //weight: 1
        $x_1_4 = "Capture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

