rule Trojan_Win64_ZigClipper_SNS_2147973490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ZigClipper.SNS!MTB"
        threat_id = "2147973490"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ZigClipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {81 f3 b9 79 37 9e c1 c3 0d 44 69 c1 65 89 07 6c 41 03 d8}  //weight: 6, accuracy: High
        $x_4_2 = {44 8b c1 42 0f b6 14 06 8b c3 c1 e8 10 0f b6 c0 33 d0 43 88 14 06 ff c1 3b cf 7c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

