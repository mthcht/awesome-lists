rule Trojan_Win64_SniperLogger_PA_2147975936_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SniperLogger.PA!MTB"
        threat_id = "2147975936"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SniperLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "SniperX_%d" ascii //weight: 5
        $x_1_2 = "\\SniperLogs" ascii //weight: 1
        $x_1_3 = "taskkill /IM" ascii //weight: 1
        $x_1_4 = "\\keylog_*.txt" ascii //weight: 1
        $x_1_5 = {4f 4b 7c 50 45 [0-8] 20 69 6e 6a 65 63 74 65 64 20 50 49 44 3d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

