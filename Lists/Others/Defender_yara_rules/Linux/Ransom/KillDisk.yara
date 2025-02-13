rule Ransom_Linux_KillDisk_A_2147772495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/KillDisk.A!MTB"
        threat_id = "2147772495"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "KillDisk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ps -axo pid > /proc_fil" ascii //weight: 1
        $x_2_2 = {48 b8 57 65 20 61 72 65 20 73 48 89 85 20 fb ff ff 48 b8 6f 20 73 6f 72 72 79 2c 48 89 85 28 fb ff ff 48 b8 20 62 75 74 20 74 68 65 48 89 85 30 fb ff ff 48 b8 20 65 6e 63 72 79 70 74 48 89 85 38 fb ff ff c7 85 40 fb ff ff 69 6f 6e 00 48 b8 6f 66 20 79 6f 75 72 20 48 89 85 80 fb ff ff 48 b8 64 61 74 61 20 68 61 73 48 89 85 88 fb ff ff 48 b8 20 62 65 65 6e 20 73 75 48 89 85 90 fb ff ff 48 b8 63 63 65 73 73 66 75 6c}  //weight: 2, accuracy: High
        $x_2_3 = {48 b8 77 69 74 68 20 62 6c 6f 48 89 85 e0 fa ff ff 48 b8 63 6b 63 68 61 69 6e 2e 48 89 85 e8 fa ff ff c7 85 f0 fa ff ff 69 6e 66 6f c6 85 f4 fa ff ff 00 48 b8 63 6f 6e 74 61 63 74 20 48 89 85 50 fb ff ff 48 b8 65 2d 6d 61 69 6c 3a 76 48 89 85 58 fb ff ff 48 b8 75 79 72 6b 35 36 38 67 48 89 85 60 fb ff ff 48 b8 6f 75 40 6c 65 6c 61 6e 48 89 85 68 fb ff ff 48 b8 74 6f 73 2e 6f 72 67 00 48 89 85 70 fb ff ff}  //weight: 2, accuracy: High
        $x_1_4 = {49 63 c7 48 c1 e0 03 48 89 f9 48 01 c8 48 8b 00 4c 31 e0 49 89 c6 49 63 c7 48 83 c0 01 48 c1 e0 03 48 01 c8 48 8b 00 4c 31 e0 48 89 c3 48 89 da 48 c1 ea 04 48 89 d8 48 c1 e0 1c 48 8d 1c 02 48 89 d8 83 e0 3f 48 83 c0 40 8b 14 85 60 36 40 00 48 89 d8 48 c1 e8 08 83 e0 3f 48 05 c0 00 00 00 8b 04 85 60 36 40 00 09 c2 48 89 d8 48 c1 e8 10 83 e0 3f 48 05 40 01 00 00 8b 04 85 60 36 40 00 09 c2 48 89 d8 48 c1 e8 18 83 e0 3f 48 05 c0 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

