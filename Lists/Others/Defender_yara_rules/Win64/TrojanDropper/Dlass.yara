rule TrojanDropper_Win64_Dlass_GVA_2147956254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win64/Dlass.GVA!MTB"
        threat_id = "2147956254"
        type = "TrojanDropper"
        platform = "Win64: Windows 64-bit platform"
        family = "Dlass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b d3 66 81 e2 ff 00 33 c9 8a 08 66 33 d1 0f b7 d2 8b 14 95 5c c5 40 00 c1 eb 08 33 d3 8b da 4e 40 85 f6 75 db}  //weight: 1, accuracy: High
        $x_2_2 = {72 44 6c 50 74 53 cd e6 d7 7b 0b 2a 01 00 00 00 39 27 6f 00 25 95 6b 00 00 a2 0a 00 02 f2 ed c3 0d 28 6b 00 00 d4 00 00 73 e1 18 29}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

