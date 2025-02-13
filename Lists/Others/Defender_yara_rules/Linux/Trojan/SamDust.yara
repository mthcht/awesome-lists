rule Trojan_Linux_SamDust_A_2147846767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SamDust.A!MTB"
        threat_id = "2147846767"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SamDust"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 4c 8d 05 01 17 0b 00 48 8d 0d 8a 16 0b 00 48 8d 3d 15 12 00 00 e8 0e fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 4c 8d 05 7a 4f 0b 00 48 8d 0d 03 4f 0b 00 48 8d 3d f7 4d 00 00 ff 15 ae 24 30 00}  //weight: 1, accuracy: High
        $x_1_3 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 4c 8d 05 44 1f 09 00 48 8d 0d cd 1e 09 00 48 8d 3d 96 ff ff ff e8 81 f5 ff ff}  //weight: 1, accuracy: High
        $x_1_4 = {31 ed 49 89 d1 5e 48 89 e2 48 83 e4 f0 50 54 4c 8d 05 21 04 0c 00 48 8d 0d aa 03 0c 00 48 8d 3d 65 54 00 00 e8 de fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Linux_SamDust_N_2147847137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/SamDust.N!MTB"
        threat_id = "2147847137"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "SamDust"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {36 34 00 42 a9 76 31 df 12 9c 1c 64 ec e0 f1 40 07 fb 15 f2 30 32 c8 20 83 4a 63 7b c8 20 83 0c 95 ae c8 93}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

