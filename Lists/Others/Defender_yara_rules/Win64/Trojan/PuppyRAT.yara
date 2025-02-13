rule Trojan_Win64_PuppyRAT_A_2147910173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PuppyRAT.A!MTB"
        threat_id = "2147910173"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PuppyRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0f b6 c0 48 ff c1 41 33 c0 44 8b c0 8a 01 45 69 c0}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 c0 33 c2 8b d0 69 d2}  //weight: 2, accuracy: High
        $x_2_3 = {41 0f b6 00 ff c9 49 ff c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

