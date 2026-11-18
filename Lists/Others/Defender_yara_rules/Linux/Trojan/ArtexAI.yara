rule Trojan_Linux_ArtexAI_GV_2147982395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/ArtexAI.GV!MTB"
        threat_id = "2147982395"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "ArtexAI"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 05 85 db 33 00 48 89 84 24 b0 00 00 00 48 8d 1d 43 de 33 00 48 89 9c 24 b8 00 00 00 48 8d 05 e7 db 33 00 48 89 84 24 c0 00 00 00 48 8d 05 25 dc 33 00 48 89 84 24 c8 00 00 00 48 8d 05 58 de 33 00 48 89 84 24 d0 00 00 00 48 8d 05 3a d8 33 00 48 89 84 24 d8 00 00 00 48 8d 05 70 3d 2c 00 48 89 84 24 e0 00 00 00 48 8d 05 e1 31 2c 00 48 89 84 24 e8 00 00 00 48 8d 05 72 3d 2c 00 48 89 84 24 f0 00 00 00 48 8d 05 4b d7 33 00 48 89 84 24 f8 00 00 00 48 8d 84 24 b0 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 01 df 4c 89 bc 24 80 00 00 00 4c 89 f5 48 8d 7c 24 10 48 8d b4 24 b0 00 00 00 e8 d6 1a 24 00 83 7c 24 10 01 75 26 48 8b 44 24 18 4c 8b 74 24 20 48 89 c3 48 29 eb 4c 89 e1 4c 29 f9 48 39 cb 0f 87 66 ff ff ff 48 39 e8 75 9b eb b3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

