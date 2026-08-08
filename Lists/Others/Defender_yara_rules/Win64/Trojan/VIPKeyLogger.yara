rule Trojan_Win64_VIPKeyLogger_GXM_2147975791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/VIPKeyLogger.GXM!MTB"
        threat_id = "2147975791"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "VIPKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {e9 03 00 00 00 cc cc cc 40 53 48 83 ec 20 48 8b d9 45 85 c0 74 08 45 8b c0 e8 e2}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

