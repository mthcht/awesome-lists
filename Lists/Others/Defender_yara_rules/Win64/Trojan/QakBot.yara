rule Trojan_Win64_QakBot_RPE_2147818245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/QakBot.RPE!MTB"
        threat_id = "2147818245"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "QakBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ANnNLsivX" ascii //weight: 1
        $x_1_2 = "BKo0kVWc" ascii //weight: 1
        $x_1_3 = "BT9yR5ta" ascii //weight: 1
        $x_1_4 = "CcmLfSZl" ascii //weight: 1
        $x_1_5 = "DSFgihgY9jp" ascii //weight: 1
        $x_1_6 = "PluginInit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

