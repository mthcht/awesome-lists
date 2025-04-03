rule Trojan_Win64_Kuping_UDP_2147937745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Kuping.UDP!MTB"
        threat_id = "2147937745"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Kuping"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {65 48 8b 04 25 60 00 00 00 48 8b 48 18 48 83 c1 20 48 89 c8 66 0f 1f 44 00 00 48 8b 00 48 39 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

