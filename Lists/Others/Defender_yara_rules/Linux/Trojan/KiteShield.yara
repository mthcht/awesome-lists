rule Trojan_Linux_KiteShield_B_2147932201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/KiteShield.B!MTB"
        threat_id = "2147932201"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "KiteShield"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ed 48 89 e7 e8 66 00 00 00 50 31 d2 31 c0 31 c9 31 f6 31 ff 31 ed 45 31 c0 45 31 c9 45 31 d2 45 31 db 45 31 e4 45 31 ed 45 31 f6 45 31 ff 5b}  //weight: 1, accuracy: High
        $x_1_2 = {49 8b 44 24 10 31 ff 49 8b 4c 24 20 41 b8 ff ff ff ff 4d 8b 54 24 08 ba 02 00 00 00 45 8b 74 24 04 48 89 c6 48 89 4c 24 18 b9 22 00 00 00 81 e6 ff 0f 00 00 49 03 74 24 28 4c 89 54 24 28 66 41 83 7f 10 03 48 89 74 24 20 40 0f 94 c7 48 25 00 f0 ff ff 45 31 c9 48 c1 e7 23 48 01 c7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_KiteShield_C_2147933831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/KiteShield.C!MTB"
        threat_id = "2147933831"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "KiteShield"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f3 0f 1e fa 49 89 f9 49 89 f2 41 89 d3 45 31 c0 48 c7 c0 0a 00 00 00 4c 89 cf 4c 89 d6 44 89 da 0f 05 41 89 c0 44 89 c0 c3 0f 1f 80 00 00 00 00 f3 0f 1e fa 41 54 41 89 f9 41 89 f3 49 89 d4 45 31 c0 48 c7 c0 65 00 00 00 44 89 cf 44 89 de 4c 89 e2 49 89 ca 0f 05 49 89 c0 4c 89 c0 41 5c c3 f3 0f 1e fa 41 54 41 89 f9 49 89 f3 41 89 d4 45 31 c0 48 c7 c0 3d 00 00 00 44 89 cf 4c 89 de 44 89 e2 49 c7 c2 00 00 00 00 0f 05 41 89 c0 44 89 c0}  //weight: 1, accuracy: High
        $x_1_2 = {44 89 cf 4c 89 de 4c 89 e2 49 89 ca 0f 05 41 89 c0 44 89 c0 41 5c c3 66 66 2e 0f 1f 84 00 00 00 00 00 f3 0f 1e fa 41 54 41 89 fb 49 89 d4 45 31 c9 55 48 89 f5 53 4c 89 c3 48 c7 c0 9d 00 00 00 44 89 df 48 89 ee 4c 89 e2 49 89 ca 49 89 d8 0f 05 41 89 c1 5b 44 89 c8 5d 41 5c c3 66 0f 1f 44 00 00 f3 0f 1e fa 49 89 f9 49 89 f2 45 31 c0 48 c7 c0 04 00 00 00 4c 89 cf 4c 89 d6 0f 05 41 89 c0 44 89 c0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

