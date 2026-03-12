rule Trojan_Win64_BadIIS_SX_2147964607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BadIIS.SX!MTB"
        threat_id = "2147964607"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BadIIS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "35"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {48 85 c0 74 ?? 48 8d ?? ?? ?? ?? ?? 48 89 ?? ?? ?? ?? ?? 48 89 ?? 45 33 c9 48 8b ?? 41 b8 01 00 00 00 [0-7] 48 8b cb 48 83 c4 20}  //weight: 20, accuracy: Low
        $x_10_2 = {48 c7 c3 ff ff ff ff 48 89 45 ?? 0f 11 44 24 ?? c7 44 24 ?? 68 00 00 00 48 8b d3 0f 11 44 24 ?? c7 44 24 ?? ff ff ff ff}  //weight: 10, accuracy: Low
        $x_3_3 = "x-real-ip: %s" ascii //weight: 3
        $x_2_4 = "\\SearchEngine" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

