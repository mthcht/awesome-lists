rule Trojan_Win64_PureRat_NV_2147981384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/PureRat.NV!MTB"
        threat_id = "2147981384"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "PureRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 4c 24 30 44 8b c1 41 c1 e8 03 8b c1 c1 e0 05 44 0b c0 44 33 c1}  //weight: 2, accuracy: High
        $x_2_2 = {8b 4c 24 40 8b 44 24 30 ff c0 03 c8 89 4c 24 30 8b 44 24 40 ff c0 89 44 24 40 8b 44 24 40 3b c2}  //weight: 2, accuracy: High
        $x_1_3 = "etc\\ho" ascii //weight: 1
        $x_1_4 = "driver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

