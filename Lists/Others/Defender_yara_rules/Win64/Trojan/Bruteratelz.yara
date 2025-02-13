rule Trojan_Win64_Bruteratelz_A_2147919883_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Bruteratelz.A!MTB"
        threat_id = "2147919883"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Bruteratelz"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 c0 41 80 f9 4c 75 2f 80 79 01 8b 75 29 80 79 02 d1 75 21 41 80 f8 b8 75 1b 80 79 06 00 75 17 0f b6 41 05 c1 e0 08 41 89 c0 0f b6 41 04 44 09 c0 01 d0 eb 02 31 c0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {49 89 ca 4c 89 c8 ff 64 24 28 49 89 ca 48 8b 44 24 30 ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

