rule Trojan_Win64_GlassWorm_2147959907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GlassWorm!MTB"
        threat_id = "2147959907"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GlassWorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4d 8b 14 01 48 8b 0c 02 4c 31 d1 4c 21 c1 49 31 ca 4d 89 14 01 48 31 0c 02 48 83 c0 08 48 83 f8 28 75 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

