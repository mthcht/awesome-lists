rule Trojan_Win64_Blackshrantac_Z_2147954864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Blackshrantac.Z!MTB"
        threat_id = "2147954864"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Blackshrantac"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 c8 80 e1 07 c0 e1 03 49 8b d0 48 d3 ea 66 41 23 d1 66 31 14 43 48 ff c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

