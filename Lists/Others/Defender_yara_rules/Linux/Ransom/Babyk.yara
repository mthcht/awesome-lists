rule Ransom_Linux_Babyk_C_2147847532_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Babyk.C!MTB"
        threat_id = "2147847532"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Babyk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/How To Restore Your Files.txt" ascii //weight: 1
        $x_1_2 = {48 8b 45 f8 0f b6 40 12 3c 08 75 77 48 8b 45 f8 48 83 c0 13 be 7b b8 40 00 48 89 c7 e8 18 fa ff ff 48 85 c0 74 5d 48 8b 55 d8 48 8b 45 e8 48 89 d6 48 89 c7 e8 50 fa ff ff 48 8b 45 e8 be 79 b8 40 00 48 89 c7 e8 ff f9 ff ff 48 8b 45 f8 48 8d 50 13 48 8b 45 e8 48 89 d6 48 89 c7 e8 e8 f9 ff ff 48 8b 45 e8 48 89 c6 bf 82 b8 40 00 b8 00 00 00 00 e8 f2 f8 ff ff 48 8b 45 e8 48 89 c7}  //weight: 1, accuracy: High
        $x_1_3 = {48 8b 55 d8 48 8b 45 e0 48 89 d1 ba 00 00 a0 00 be 01 00 00 00 48 89 c7 e8 a2 fc ff ff 48 89 45 c8 48 8b 45 c8 48 01 45 c0 48 83 7d c8 00 0f 84 86 00 00 00 48 8b 4d c8 48 8b 55 e0 48 8b 5d e0 48 8d 85 60 fe ff ff 48 89 de 48 89 c7 e8 8b a7 00 00 48 8b 45 c8 48 f7 d8 48 89 c1 48 8b 45 d8 ba 01 00 00 00 48 89 ce 48 89 c7 e8 7f fb ff ff 48 8b 4d d8 48 8b 55 c8 48 8b 45 e0 be 01 00 00 00 48 89 c7 e8 96 fc ff ff 48 81 7d c0 ff ff ff 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

