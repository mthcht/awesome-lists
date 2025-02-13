rule Ransom_Linux_CLOP_A_2147840860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/CLOP.A!MTB"
        threat_id = "2147840860"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "CLOP"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C_I_0P" ascii //weight: 1
        $x_1_2 = "Jfkdskfku2ir32y7432uroduw8y7318i9018urewfdsZ2Oaifwuieh~~cudsffdsd" ascii //weight: 1
        $x_1_3 = {8b 45 e8 89 44 24 0c 8b 45 e4 89 44 24 08 c7 44 24 04 [0-6] 8d 85 [0-6] 89 04 24 e8 [0-6] b8 20 24 14 08 b9 ff ff ff ff 89 85 [0-6] b8 [0-6] fc 8b bd [0-6] f2 ae 89 c8 f7 d0 83 e8 01 89 [0-4] 8b [0-4] 0f b7 d0 c7 44 24 [0-6] 8d 85 [0-6] 89 44 24 08 89 54 24 04 c7 04 24 [0-6] e8 [0-6] 8d 85 [0-6] 89 44 24 04 8b 45 08 89 04 24 e8 [0-6] 8b 45 e8 89 44 24 04 8b 45 e4 89 04 24 e8}  //weight: 1, accuracy: Low
        $x_1_4 = {c7 44 24 04 [0-6] c7 04 24 [0-6] e8 [0-6] c7 04 24 ff ff ff ff e8 [0-6] c9 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 45 a0 25 00 f0 00 00 3d 00 40 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

