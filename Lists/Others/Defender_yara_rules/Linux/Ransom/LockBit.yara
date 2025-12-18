rule Ransom_Linux_LockBit_A_2147811314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockBit.A!MTB"
        threat_id = "2147811314"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 e9 41 c1 e1 10 44 31 c8 44 0f b6 8d ?? ?? 42 00 89 cd c1 ed 10 40 0f b6 ed 41 c1 e1 18 44 31 c8 44 0f b6 8d ?? ?? 42 00 41 c1 e1 08 44 31 c8 31 c7 89 82 ?? 00 00 00 83 f0 1b 31 fe 41 89 7a 14 31 f1 41 89 72 18 0f b6 ed}  //weight: 2, accuracy: Low
        $x_2_2 = {44 0f b6 c9 45 0f b6 89 ?? ?? 42 00 41 c1 e1 18 44 31 c8 41 89 c9 41 c1 e9 10 45 0f b6 c9 45 0f b6 89 ?? ?? 42 00 41 c1 e1 08 44 31 c8 31 c7 89 82 a0 00 00 00 83 f0 36 31 fe 41 89 78 14 89 f2 41 89 70 18 31 ca 0f b6 ce}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_LockBit_B_2147845304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockBit.B!MTB"
        threat_id = "2147845304"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5a 5c 50 4f 5c 19 5f 50 57 5c 4a 19 5f 4b 56 54 19 4d 51 5c 19 5e 56 4f 5c 4b 57 54 5c 57 4d 19 4a 4c 5a 51 19 58 4a 19 4d 51 5c 19 7e 7d 6b 69 19 58 57 5d 19 54 58 57 40 19 56 4d 51 5c 4b 4a 15 19 40 56 4c 19 5a 58 57 19 5b 5c 19 4a 4c 5c 5d 19 5b 40 19 5a 4c}  //weight: 1, accuracy: High
        $x_1_2 = "restore-my-files.txt" ascii //weight: 1
        $x_1_3 = "bootsect.bak" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_LockBit_C_2147901586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockBit.C!MTB"
        threat_id = "2147901586"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f b6 81 6a 75 64 00 31 d0 88 81 6a 75 64 00 48 83 c1 01 84 c0 75 e9}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 04 31 0f b6 14 39 48 01 d0 4c 01 c8 88 04 39 49 89 c1 48 83 c1 01 49 c1 e9 08 4c 39 c1 75 df}  //weight: 1, accuracy: High
        $x_1_3 = {ba ff ff ff ff be 01 00 00 00 48 89 ef e8 c1 fd fe ff 85 c0 79 2c 41 8b 04 24 83 f8 04 74 e1 83 f8 0b 74 dc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_LockBit_D_2147907541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockBit.D!MTB"
        threat_id = "2147907541"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {48 89 c8 31 d2 4c 01 e1 48 f7 f3 31 d2 48 89 c6 48 89 c8 48 0f af f3 48 29 f0 48 89 37 48 f7 f3 31 d2 49 89 c1 4c 89 d0 48 f7 f3 49 39 c1 4c 0f 47 c8 49 83 c0 01 44 89 4f 08 48 83 c7 0c 4c 39 45 00}  //weight: 2, accuracy: High
        $x_2_2 = {0f b6 f7 89 ff 45 33 01 45 89 ed 4c 89 f0 44 33 04 b5 a0 6a 43 00 89 ce 0f b6 c4 c1 ee 10 40 0f b6 f6 44 33 04 b5 a0 6e 43 00 41 0f b6 f6 8b 34 b5 a0 66 43 00 33 34 bd a0 72 43 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_LockBit_E_2147909860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockBit.E!MTB"
        threat_id = "2147909860"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 66 2e 0f 1f 84 00 00 00 00 00 0f b7 77 38 4c 8b 97 a7 00 00 00 41 b9 02 00 00 00 0f af 77 3a 45 8b 82 ec 01 00 00 44 89 c0 c1 ee 02 66 0f 1f 44 00 00 83 c0 01 39 c6 41 0f 42 c1 44 39 c0 74 14 48 8b 57 46 89 c1 8b 14 8a 85 d2 75 e5 41 89 82 ec 01 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 47 77 0f b7 57 38 83 ee 02 48 0f af c2 48 0f af c6 48 03 47 5e c3 0f 1f 84 00 00 00 00 00 0f b6 47 77 0f b7 57 38 83 ee 02 48 0f af c2 48 0f af c6 48 03 47 5e c3}  //weight: 1, accuracy: High
        $x_1_3 = {31 c0 48 85 ff 74 1c 66 83 3f 00 48 89 fa 74 13 48 83 c2 02 66 83 3a 00 75 f6 48 89 d0 48 29 f8 48 d1 f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_LockBit_F_2147916314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockBit.F!MTB"
        threat_id = "2147916314"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 84 1d 00 00 00 bb 60 d5 43 00 0f 1f 44 00 00 48 83 eb 08 ff d0 48 8b 03 48 83 f8 ff 0f 85 ed ff ff ff 48 83 c4 08}  //weight: 1, accuracy: High
        $x_1_2 = {0f 84 2a 00 00 00 e8 a6 1b 00 00 48 89 c2 b8 60 b4 43 00 48 8b 4c 24 18 48 8d 9c 24 10 11 00 00 48 89 de 48 89 c7 b8 00 00 00 00 e8 87 1b 00 00 48 8b 44 24 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_LockBit_I_2147918606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockBit.I!MTB"
        threat_id = "2147918606"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 1a f2 ff ff 31 db b8 78 b9 65 00 b9 78 b9 65 00 48 29 c1 48 89 c8 48 c1 f8 3f 48 c1 e8 3d 48 01 c8 48 c1 f8 03 74 48 b8 78 b9 65 00 b9 78 b9 65 00 48 29 c1 49 89 cc 49 c1 fc 3f 49 c1 ec 3d 49 01 cc 49 c1 fc 03 0f 1f 84 00 00 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 c4 08 5b 5d 41 5c 41 5d c3 e8 66 ee ff ff 83 38 23 74 cb 90 e8 5b ee ff ff 83 38 23 74 c0 48 89 d8 eb db}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_LockBit_G_2147953086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockBit.G!MTB"
        threat_id = "2147953086"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "should_bypass_dir" ascii //weight: 1
        $x_1_2 = "should_bypass_file" ascii //weight: 1
        $x_1_3 = "clear_bypass_caches" ascii //weight: 1
        $x_1_4 = {44 0f b6 66 0d 48 83 c6 10 41 c1 e5 10 41 c1 e7 18 41 c1 e4 08 45 09 ec 44 8b 6c 24 ec 45 09 f4 4d 89 c6 45 09 fc 4c 8b 7c 24 f0 4c 01 e1 49 89 fc 4c 0f af e3 4d 0f af f1 4d 01 e6 49 89 d4 44 0f af e8 4c 0f af f9 4c 0f af e5 4d 01 ee 4d 89 c5 4d 01 fe 49 89 ff}  //weight: 1, accuracy: High
        $x_1_5 = {4c 33 57 20 48 01 c5 49 31 d8 48 03 5f 68 49 31 e9 49 c1 c0 20 49 c1 c1 30 48 33 6f 10 4d 01 c4 4d 01 cf 4c 33 4f 28 4c 31 e6 48 33 6c 24 d8 4c 31 f8 48 c1 c6 28 4c 33 3f 48 01 f3 4c 33 7c 24 d0 49 31 d8 48 33 5f 18 4c 31 c9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_LockBit_H_2147956018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/LockBit.H!MTB"
        threat_id = "2147956018"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "LockBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "LockBit 5.0" ascii //weight: 1
        $x_1_2 = "/ReadMeForDecrypt.txt" ascii //weight: 1
        $x_1_3 = ".LOCKER" ascii //weight: 1
        $x_1_4 = "encrypt_extension" ascii //weight: 1
        $x_1_5 = "/bin/vim-cmd vmsvc/getallvms" ascii //weight: 1
        $x_2_6 = {74 74 70 3a 2f 2f 6c 6f 63 6b 62 69 74 [0-80] 2e 6f 6e 69 6f 6e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

