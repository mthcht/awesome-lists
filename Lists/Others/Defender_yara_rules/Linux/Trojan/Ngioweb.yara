rule Trojan_Linux_Ngioweb_A_2147764010_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ngioweb.A!MTB"
        threat_id = "2147764010"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ngioweb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 39 d6 74 0b 40 30 3e 48 ff c6 c1 cf 08 eb f0}  //weight: 1, accuracy: High
        $x_1_2 = {c6 44 24 2e 73 c6 44 24 2d 73 c6 44 24 2c 64 c6 44 24 2b 73 c6 44 24 2a 64 c6 44 24 29 73 c6 44 24 28 64 c6 44 24 27 66 c6 44 24 26 72 c6 44 24 25 69 c6 44 24 24 75 c6 44 24 23 79 c6 44 24 22 74 c6 44 24 21 66 c6 44 24 20 64 c6 44 24 1f 73 c6 44 24 1e 61 c6 44 24 1d 72 c6 44 24 1c 65 c6 44 24 1b 77 c6 44 24 1a 71 c6 44 24 19 63 c6 44 24 18 78 c6 44 24 17 7a c6 44 24 16 66 c6 44 24 15 64 c6 44 24 14 73 c6 44 24 13 61 c6 44 24 12 72 c6 44 24 11 65 c6 44 24 10 77 c6 44 24 0f 71}  //weight: 1, accuracy: High
        $x_1_3 = {c6 44 24 1e 64 c6 44 24 1d 69 48 8d 7c 24 10 c6 44 24 1c 2d c6 44 24 1b 65 c6 44 24 1a 6e c6 44 24 19 69 c6 44 24 18 68 c6 44 24 17 63 c6 44 24 16 61 c6 44 24 15 6d c6 44 24 14 2f c6 44 24 13 63 c6 44 24 12 74 c6 44 24 11 65 c6 44 24 10 2f}  //weight: 1, accuracy: High
        $x_1_4 = {c6 43 03 74 c6 43 02 65 c6 43 01 6e eb 1e c6 43 04 6f c6 43 03 66 c6 43 02 6e c6 43 01 69 eb 44 c6 43 03 6d c6 43 02 6f c6 43 01 63 c6 03 2e c6 43 04 00 e9 f2 02 00 00 c6 43 03 7a c6 43 02 69 c6 43 01 62 eb e6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Linux_Ngioweb_B_2147892648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Ngioweb.B!MTB"
        threat_id = "2147892648"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Ngioweb"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 01 0c b7 33 7a a5 cb 1e 84 c2 5b 21 f0 a9 93 60 01 0c b7 33 2d 7d 48 9f 4e a3 83 16 22 1d f8 6b bb 2d d5 f2 e4 3d 8b 65 2e 43 81 cf 8f bc 67 85 b7 ec 75 5f 7a a5 cb 1e 84 c2 5b 21 f0 a9 93 60 01 0c b7 33 7a a5 cb 1e 84 c2 5b 21 f0 a9 93 60 01 0c b7 33 a0 bf a9 bc d2 27 b5 35 62 76 35 ea 0c 5b 4e aa b5 53 3f 43 05 e6 35 59 28 d6 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

