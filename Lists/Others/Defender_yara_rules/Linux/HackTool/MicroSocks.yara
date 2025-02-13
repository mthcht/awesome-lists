rule HackTool_Linux_MicroSocks_A_2147820253_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/MicroSocks.A!MTB"
        threat_id = "2147820253"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "MicroSocks"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 45 d8 48 8d 95 c0 fd ff ff 48 8b 75 d8 8b 45 fc b9 00 01 00 00 89 c7 e8 ?? ?? ff ff 0f b7 75 e6 48 8b 85 a8 fd ff ff 8b 40 1c 48 8d 8d d0 fe ff ff 48 8d 95 c0 fd ff ff 41 89 f1 49 89 c8 48 89 d1 89 c2 be d8 29 40 00 bf 02 00 00 00 b8 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {0f 95 c0 48 8d 74 83 0c 4c 8d bc 24 a0 08 00 00 b9 00 01 00 00 4c 89 fa e8 ?? f3 ff ff 8b 53 24 48 8d 35 7c 03 00 00 4c 8d 84 24 20 04 00 00 bf 02 00 00 00 31 c0 4c 89 f9 41 89 e9 e8 ?? f2 ff ff 8b 7b 24}  //weight: 1, accuracy: Low
        $x_1_3 = {48 89 45 f8 48 8d 95 c0 fd ff ff 48 8b 75 f8 8b 7d dc b9 00 01 00 00 e8 ?? ?? ff ff 0f b7 55 f2 48 8b 85 a8 fd ff ff 8b 70 1c 48 8d 85 d0 fe ff ff 48 8d 8d c0 fd ff ff 41 89 d1 49 89 c0 89 f2 be 58 2b 40 00 bf 02 00 00 00 b8 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

