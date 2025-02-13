rule Trojan_Win64_Zegost_SAG_2147929678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zegost.SAG!MTB"
        threat_id = "2147929678"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zegost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 f7 04 00 00 48 83 c4 28 e9 09 10 ff ff cc cc 40 53 48 83 ec 20 48 8b d9 33 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

