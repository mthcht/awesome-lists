rule Trojan_Win64_Raktu_AO_2147840243_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Raktu.AO!MTB"
        threat_id = "2147840243"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Raktu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 85 28 4f 04 00 48 98 0f b6 54 05 b0 8b 85 2c 4f 04 00 48 98 0f b6 84 05 f0 4e 04 00 31 c2 8b 85 28 4f 04 00 48 98 88 94 05 50 27 02 00 83 85 2c 4f 04 00 01 83 85 28 4f 04 00 01 8b 85 28 4f 04 00 3d 99 27 02 00 76}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

