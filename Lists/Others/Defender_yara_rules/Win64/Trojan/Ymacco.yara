rule Trojan_Win64_Ymacco_YAA_2147906591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Ymacco.YAA!MTB"
        threat_id = "2147906591"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Ymacco"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 8b c0 83 e0 3f 2b c8 48 d3 cf 48 8d 0d ?? ?? ?? ?? 49 33 f8 4a 87 bc f1 10 f5 01 00 33 c0}  //weight: 10, accuracy: Low
        $x_1_2 = {2b d1 8a ca 50 90 5a 48 d3 ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

