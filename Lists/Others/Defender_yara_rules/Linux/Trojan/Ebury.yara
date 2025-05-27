rule Trojan_Linux_Ebury_B_2147822295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ebury.B!MTB"
        threat_id = "2147822295"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ebury"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 83 e0 03 ff c0 42 32 4c 04 f0 88 cb 83 e1 0f c0 eb 04 44 0f b6 c3 46 8a 84 02 65 0d 00 00 44 88 06 8a 8c 0a 65 0d 00 00 88 4e 01 48 83 c6 02 41 89 c0 42 8a 0c 07 84 c9 75 c5 c6 06 00 5b c3}  //weight: 1, accuracy: High
        $x_1_2 = {89 c0 4c 89 ef 48 c1 e0 04 48 8b 74 28 08 e8 30 fd ff ff 48 85 c0 74 0e 41 83 fc 01 75 05 48 89 c3 eb 17 48 89 c3 ff 05 14 bc 20 00 8b 05 0e bc 20 00 3b 05 04 bc 20 00 72 c6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_Ebury_C_2147823817_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ebury.C!MTB"
        threat_id = "2147823817"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ebury"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 10 48 39 da 74 3e 48 85 d2 75 1a b2 03 48 89 df 89 ed ff 15 e8 85 20 00 48 8d 05 31 c7 20 00 48 89 1c e8 eb 1f ff c5 48 83 c0 08 83 fd 04 75 ce}  //weight: 1, accuracy: High
        $x_1_2 = {49 89 f9 ff c7 41 83 e1 03 46 8a 4c 0c f0 44 32 0a 48 ff c2 44 88 cb 41 83 e1 0f c0 eb 04 44 0f b6 d3 46 8a 94 10 ad 0c 00 00 45 88 10 46 8a 8c 08 ad 0c 00 00 45 88 48 01 49 83 c0 02 39 cf 72 bf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_Ebury_D_2147844751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ebury.D!MTB"
        threat_id = "2147844751"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ebury"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 f9 2f 41 89 e9 44 0f 45 cb 44 88 c1 c1 e1 04 41 88 cb 44 88 c9 c0 e9 02 41 88 cc 8a 4e 03 45 09 dc 80 f9 3d}  //weight: 1, accuracy: High
        $x_1_2 = {41 83 e0 03 ff c0 42 32 4c 04 f0 88 cb 83 e1 0f c0 eb 04 44 0f b6 c3 46 8a 84 02 f2 0d 00 00 44 88 06 8a 8c 0a f2 0d 00 00 88 4e 01 48 83 c6 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Ebury_E_2147942305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ebury.E!MTB"
        threat_id = "2147942305"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ebury"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 e8 02 31 d2 45 31 c9 45 31 e4 41 c1 e2 02 41 c0 e8 04 44 88 67 01 45 09 d0 44 88 4f 02 83 ea 04 44 88 07 48 83 c6 04 48 83 c7 03 85 d2 0f 8f 9d fe ff ff 5b 5d 41 5c c3}  //weight: 2, accuracy: High
        $x_2_2 = {89 e8 8b 4b 60 c1 e8 06 23 43 5c 89 c0 48 8b 04 c2 89 ea d3 ea 89 d1 83 e1 3f 48 89 c2 48 d3 ea 89 e9 83 e1 3f 48 d3 e8 48 85 c2 0f 84 44 01 00 00 31 d2 89 e8}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

