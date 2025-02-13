rule Trojan_Linux_Perfctl_B_2147923938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Perfctl.B!MTB"
        threat_id = "2147923938"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Perfctl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 3d f9 33 00 00 48 8d 35 f2 33 00 00 48 29 fe 48 89 f0 48 c1 ee 3f 48 c1 f8 03 48 01 c6 48 d1 fe 74 14 48 8b 05 d5 2d 00 00 48 85 c0 74 08 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {80 3d f1 33 00 00 00 75 2f 55 48 83 3d b6 2d 00 00 00 48 89 e5 74 0c 48 8b 3d 7a 2e 00 00 e8 2d ff ff ff e8 68 ff ff ff c6 05 c9 33 00 00 01 5d c3 0f 1f 80 00 00 00 00 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Perfctl_D_2147923940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Perfctl.D!MTB"
        threat_id = "2147923940"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Perfctl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 3d 79 32 00 00 48 8d 35 72 32 00 00 48 29 fe 48 89 f0 48 c1 ee 3f 48 c1 f8 03 48 01 c6 48 d1 fe 74 14 48 8b 05 d5 2d 00 00 48 85 c0 74 08 ff e0}  //weight: 1, accuracy: High
        $x_1_2 = {55 48 89 e5 48 81 ec 30 01 00 00 48 89 bd d8 fe ff ff 48 8d 95 70 ff ff ff 48 8b 85 d8 fe ff ff 48 89 d6 48 89 c7 e8 8a 08 00 00 85 c0 79 0a b8 ff ff ff ff e9 8c 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Perfctl_A_2147923949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Perfctl.A!MTB"
        threat_id = "2147923949"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Perfctl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8d 3d 49 0e 21 00 48 8d 05 49 0e 21 00 55 48 29 f8 48 89 e5 48 83 f8 0e 76 15 48 8b 05 ae d9 20 00 48 85 c0 74 09 5d ff e0 66 0f 1f 44 00 00 5d c3 0f 1f 40 00 66 2e 0f 1f 84 00 00 00 00 00 48 8d 3d 09 0e 21 00 48 8d 35 02 0e 21 00 55 48 29 fe 48 89 e5 48 c1 fe 03}  //weight: 1, accuracy: High
        $x_1_2 = {80 3d b9 0d 21 00 00 75 27 48 83 3d 67 d9 20 00 00 55 48 89 e5 74 0c 48 8b 3d 42 dc 20 00 e8 3d ff ff ff e8 48 ff ff ff 5d c6 05 90 0d 21 00 01 f3 c3 0f 1f 40 00 66 2e 0f 1f 84 00 00 00 00 00 48 8d 3d f1 d6 20 00 48 83 3f 00 75 0b e9 5e ff ff ff 66 0f 1f 44 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Perfctl_C_2147923951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Perfctl.C!MTB"
        threat_id = "2147923951"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Perfctl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 e4 c1 e8 04 83 f8 01 74 29 83 f8 01 72 07 83 f8 02 74 49 eb 67 8b 45 f8 23 45 f4 89 c2 8b 45 f8 f7 d0 23 45 f0 09 d0 89 45 ec 8b 45 e4 89 45 e8 eb 69}  //weight: 1, accuracy: High
        $x_1_2 = {8d 50 01 89 55 fc 8b 4d f8 48 8b 55 a0 48 01 ca 0f b6 0a 48 8b 55 a8 89 c0 88 4c 02 18 8b 45 fc 83 e0 3f 85 c0 0f 85 a6 00 00 00 c7 45 f4 00 00 00 00 eb 79 8b 45 f4 c1 e0 02 8d 50 03 48 8b 45 a8 89 d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

