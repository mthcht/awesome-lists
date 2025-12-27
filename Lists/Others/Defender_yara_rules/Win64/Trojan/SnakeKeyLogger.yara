rule Trojan_Win64_SnakeKeyLogger_GX_2147949171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SnakeKeyLogger.GX!MTB"
        threat_id = "2147949171"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 0f b6 54 05 00 31 c2 83 f2 24 41 88 54 05 00 48 83 c0 01 39 c1 7f e8}  //weight: 2, accuracy: High
        $x_1_2 = "BND_%08X.tmp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

