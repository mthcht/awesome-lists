rule Trojan_Win64_Xegumumune_SX_2147965831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Xegumumune.SX!MTB"
        threat_id = "2147965831"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Xegumumune"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "45"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "Kong\\Keylogger" ascii //weight: 30
        $x_10_2 = "Software\\Kong\\Client\\ClientVersion" ascii //weight: 10
        $x_5_3 = "[Local\\ClientMutex_%08X" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

