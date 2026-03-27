rule Trojan_Win64_SpyAgent_CX_2147965817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SpyAgent.CX!MTB"
        threat_id = "2147965817"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SpyAgent"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "captureAndProcessScreenshot" ascii //weight: 5
        $x_5_2 = "beaconLoop" ascii //weight: 5
        $x_5_3 = "detectAVProducts" ascii //weight: 5
        $x_5_4 = "executePE5Exploit" ascii //weight: 5
        $x_5_5 = "TelegramC2Handler" ascii //weight: 5
        $x_5_6 = "handleExfiltrate" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

