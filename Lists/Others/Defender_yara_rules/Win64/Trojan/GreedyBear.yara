rule Trojan_Win64_GreedyBear_NG_2147962192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/GreedyBear.NG!MTB"
        threat_id = "2147962192"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "GreedyBear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 8d 10 01 00 00 0f b6 85 28 01 00 00 0f b6 8d 2f 01 00 00 c1 e1 10 0f b7 95 2d 01 00 00 09 ca 48 c1 e2 20 8b 8d 29 01 00 00 48 09 d1 48 8b 9d 30 01 00 00 48 c1 e1 08 48 09 c1 48 89 8d a0 01 00 00 48 8d 8d 80 01 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {48 8d 41 ff 48 89 85 c8 00 00 00 48 8b 41 ff 48 89 85 b0 01 00 00 48 8b 41 07 48 89 85 68 01 00 00 48 8b 00 48 85 c0 74 09 48 8b 8d b0 01 00 00 ff d0}  //weight: 1, accuracy: High
        $x_1_3 = "Voxtek Trust Us With Your Safety" wide //weight: 1
        $x_1_4 = "absolute_solver" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

