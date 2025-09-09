rule Ransom_Linux_Filecoder_B_2147779611_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.B!MTB"
        threat_id = "2147779611"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "!NEWS_FOR_STJ!.txt" ascii //weight: 1
        $x_1_2 = ".stj888" ascii //weight: 1
        $x_1_3 = "Your files are fully CRYPTED" ascii //weight: 1
        $x_1_4 = "g_RansomHeader" ascii //weight: 1
        $x_1_5 = "!NOTICE_FOR_PETRAMINA!.tXt" ascii //weight: 1
        $x_1_6 = ".p3tr4m1n4" ascii //weight: 1
        $x_1_7 = "encrypt_worker" ascii //weight: 1
        $x_1_8 = {e8 69 e3 00 00 48 83 c4 10 89 45 cc 83 7d cc 00 0f 85 af 00 00 00 48 8d 3d 12 ac 02 00 e8 0d fc ff ff 48 8b 85 e0 e8 ff ff 48 8b 95 e8 e8 ff ff 48 89 05 38 ae 02 00 48 89 15 39 ae 02 00 48 8b 85 f0 e8 ff ff 48 8b 95 f8 e8 ff ff 48 89 05 2c ae 02 00 48 89 15 2d ae 02 00 48 8b 95 78 ee ff ff 48 8d 85 c0 ef ff ff 48 89 c6 48 8d 3d fd ab 02 00 e8 dd fc ff ff 48 8d 3d b1 ab 02 00 e8 fc fa ff ff c7 45 dc 01 00 00 00 48 8d 85 70 ee ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_Linux_Filecoder_G_2147788515_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.G!MTB"
        threat_id = "2147788515"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "!_RENNER_README_!.txt" ascii //weight: 2
        $x_2_2 = "g_RansomHeader" ascii //weight: 2
        $x_1_3 = "encrypt_worker" ascii //weight: 1
        $x_1_4 = ".r3nn3r" ascii //weight: 1
        $x_1_5 = "Your files were encrypted." ascii //weight: 1
        $x_1_6 = "GetRansomConfig" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Filecoder_D_2147809996_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.D!MTB"
        threat_id = "2147809996"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {48 89 c7 e8 ?? ?? ff ff 89 85 4c ff ff ff 8b 85 4c ff ff ff 83 e8 04 48 98 48 8d 50 10 48 8b 85 58 ff ff ff 48 01 d0 48 83 c0 03 48 89 85 60 ff ff ff 48 8b 85 60 ff ff ff 48 8d 35 73 0b 00 00 48 89 c7 e8 ?? ?? ff ff 85 c0}  //weight: 2, accuracy: Low
        $x_2_2 = {48 89 c1 ba 50 00 00 00 be 01 00 00 00 48 8d 3d 65 09 00 00 e8 ?? ?? ff ff 48 8b 45 98 48 89 c7 e8 ?? ?? ff ff 48 8d 4d a0 48 8d 55 c0 48 8b 75 ?? ?? 8b 45 88 48 89 c7 e8 ?? ?? 00 00 48 8b 45 88 48 89 c7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_E_2147816007_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.E!MTB"
        threat_id = "2147816007"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {e8 5e a8 fb ff 48 8b 84 24 10 08 00 00 69 f0 e8 03 00 00 48 8b 8c 24 18 08 00 00 48 ba cf f7 53 e3 a5 9b c4 20 48 89 c8 48 f7 ea 48 c1 fa 07 48 89 c8 48 c1 f8 3f 48 29 c2 48 89 d0 01 f0 89 c7 e8 be a6 fb ff 48 8b 05 ff 43 21 00 48 89 c1 ba 1a 00 00 00 be 01 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = ".nuctech-gj0okyci" ascii //weight: 1
        $x_1_3 = "|.txt|.js|.xml|.mat|.doc|.xlsx|.htm|.xls|.docx|.py|.h|.html" ascii //weight: 1
        $x_1_4 = "readme_to_nuctech.txt" ascii //weight: 1
        $x_1_5 = "--disable-ransomfile" ascii //weight: 1
        $x_1_6 = "encrypt_decrypt_files_after_years" ascii //weight: 1
        $x_1_7 = "oLoCOInaFX@onionmail.org" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Linux_Filecoder_H_2147817430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.H!MTB"
        threat_id = "2147817430"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You have been PWNED!" ascii //weight: 1
        $x_1_2 = "xxxyy@yandex.ru" ascii //weight: 1
        $x_1_3 = "Hear me ROAR All files belong to me and are in an encrypted state. I have but two simple commands." ascii //weight: 1
        $x_1_4 = "/etc/shadow" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_J_2147831781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.J!MTB"
        threat_id = "2147831781"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Randomware by [afjoseph]" ascii //weight: 1
        $x_1_2 = "randomware" ascii //weight: 1
        $x_1_3 = "encrypt_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_K_2147847540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.K!MTB"
        threat_id = "2147847540"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Randomware by [afjoseph]" ascii //weight: 2
        $x_2_2 = "byte_to_xor =" ascii //weight: 2
        $x_1_3 = "osiris" ascii //weight: 1
        $x_1_4 = "key is:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Linux_Filecoder_L_2147847690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.L!MTB"
        threat_id = "2147847690"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encryptData" ascii //weight: 1
        $x_1_2 = "main.isPayed" ascii //weight: 1
        $x_1_3 = "main.selfRemove" ascii //weight: 1
        $x_1_4 = "createAndShowMessage" ascii //weight: 1
        $x_1_5 = "doSomeThingElseWithDebugger" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_P_2147848246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.P!MTB"
        threat_id = "2147848246"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encryptFile" ascii //weight: 1
        $x_1_2 = "saveKeyToFile" ascii //weight: 1
        $x_1_3 = "generateKey" ascii //weight: 1
        $x_1_4 = ".crypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_M_2147848693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.M!MTB"
        threat_id = "2147848693"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dropRansomNote" ascii //weight: 1
        $x_1_2 = "writeEncryptedData" ascii //weight: 1
        $x_1_3 = "dirtyLocked" ascii //weight: 1
        $x_1_4 = "encryptor/fileDetection" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_N_2147848694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.N!MTB"
        threat_id = "2147848694"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MetaEncrypter.txt" ascii //weight: 1
        $x_1_2 = "--disable-ransomfile" ascii //weight: 1
        $x_1_3 = ".metencrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_S_2147849015_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.S!MTB"
        threat_id = "2147849015"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.encrypt" ascii //weight: 1
        $x_1_2 = "main.GetHomeDir" ascii //weight: 1
        $x_1_3 = "readMe" ascii //weight: 1
        $x_1_4 = "/root/cry/encrypt.go" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_O_2147850528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.O!MTB"
        threat_id = "2147850528"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 85 f8 fb ff ff 8b 85 e8 fb ff ff 48 63 d0 48 8b 8d f8 fb ff ff 48 8d 85 10 fc ff ff be 01 00 00 00 48 89 c7}  //weight: 1, accuracy: High
        $x_1_2 = "encryptfile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_R_2147850533_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.R!MTB"
        threat_id = "2147850533"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 95 b8 fe ff ff 8b 85 98 fe ff ff 48 98 0f b6 04 02 89 c1 8b 85 84 fe ff ff 48 63 d0 48 69 d2 67 66 66 66 48 c1 ea 20 c1 fa 02 c1 f8 1f 29 c2 89 d0 01 c8 89 c1 48 8b 95 b8 fe ff ff 8b 85 98 fe ff ff 48 98 88 0c 02 83 85 98 fe ff ff 01 8b 85 98 fe ff ff 3b 85 9c fe ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "encryptDir" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_V_2147852393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.V!MTB"
        threat_id = "2147852393"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "R3d41&t_C2." ascii //weight: 1
        $x_1_2 = "curl_easy_perf" ascii //weight: 1
        $x_1_3 = "t/-dex.php?c0m6=" ascii //weight: 1
        $x_1_4 = {dd 2e 74 2f 2d 64 65 78 2e 70 68 70 3f 63 30 6d 36 3d ef 01 fb b7 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_X_2147891314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.X!MTB"
        threat_id = "2147891314"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "randomware" ascii //weight: 1
        $x_1_2 = ".Chaos" ascii //weight: 1
        $x_1_3 = "encrypt_file" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_Y_2147906079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.Y!MTB"
        threat_id = "2147906079"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 89 54 24 18 48 89 44 24 28 4b 8d 04 00 48 8d 40 02 48 c1 e0 03 31 db b9 01 00 00 00 e8 b3 27 00 00 48 89 44 24 20 48 8b 54 24 18 48 8b 32 48 d1 e6 48 89 30 44 0f 11 7c 24 30 48 8d 35 73 a6 05 00 48 89 74 24 30 48 89 44 24 38 48 8d 44 24 30 0f 1f 40 00 e8 fb 0e 00 00 48 8b 5c 24 20 48 8b 53 08 48 8b 74 24 18 48 39 56 08 75 46}  //weight: 1, accuracy: High
        $x_1_2 = {44 6f 01 02 44 70 01 02 44 71 01 02 46 64 01 02 47 78 01 02 47 79 01 02 48 69 01 02 49 44 01 02 49 50 01 02 49 64 01 02 49 6e 01 02 49 70 01 02 49 73 01 02 4c 6f 01 02 4f 70 01 02 4f 72 01 02 50 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_AB_2147927738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.AB!MTB"
        threat_id = "2147927738"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 0f 6f 0d 51 42 15 00 66 0f 6f 05 59 42 15 00 48 b8 7c 6f 6b 6e 2a 2f 7e 67 41 ba 2a 2f 00 00 c6 85 5b fc ff ff 00 0f 29 8d d0 fd ff ff 48 89 85 50 fc ff ff 0f 29 85 e0 fd ff ff 66 44 89 95 58 fc ff ff 48 89 85 f0 fd ff ff c6 85 5a fc ff ff 80 8b 85 58 fc ff ff 0f 29 8d 30 fc ff ff 89 85 f8 fd ff ff 31 c0 0f 29 85 40 fc ff ff 0f 1f 00}  //weight: 1, accuracy: High
        $x_1_2 = {0f b6 94 05 20 fd ff ff 83 ea 04 88 94 05 20 fd ff ff 48 83 c0 01 48 83 f8 2a 75 e4 e8 1f 4e 02 00 4c 8b a0 30 01 00 00 41 8b 5c 24 40 45 0f b6 b4 24 90 00 00 00 83 fb 02 0f 8e 31 32 00 00 45 84 f6 0f 85 28 32 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_Z_2147928901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.Z!MTB"
        threat_id = "2147928901"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 83 ec 10 48 83 e4 f0 bf 01 00 00 00 48 8d 34 24 48 8b 05 95 4a 1c 00 48 83 f8 00 74 3e ff d0 48 8b 04 24 48 8b 54 24 08 4c 89 e4 48 8b 4c 24 08 48 89 8b 20 03 00 00 48 8b 0c 24 48 89 8b 28 03 00 00 48 69 c0 00 ca 9a 3b 48 01 d0 48 89 44 24 20 48 8b 6c 24 10 48 83 c4 18 c3 48 c7 c0 e4 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {48 83 ec 18 48 89 6c 24 10 48 8d 6c 24 10 49 89 e4 49 8b 5e 30 48 8b 8b 28 03 00 00 48 8b 93 20 03 00 00 48 89 0c 24 48 89 54 24 08 48 8d 54 24 20 48 8b 4a f8 48 89 8b 28 03 00 00 48 89 93 20 03 00 00 4c 3b b3 c0 00 00 00 75 07 48 8b 13 48 8b 62 38 48 83 ec 20 48 83 e4 f0 bf 00 00 00 00 48 8d 74 24 10 48 8b 05 74 43 1c 00 48 83 f8 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_AA_2147935640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.AA!MTB"
        threat_id = "2147935640"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/root/sougolock-linux.go" ascii //weight: 1
        $x_1_2 = {48 89 bc 24 88 00 00 00 48 89 74 24 68 48 01 f8 48 89 04 24 48 89 54 24 08 48 89 4c 24 10 e8 0a 44 f6 ff 48 8b 44 24 58 48 8b 8c 24 b8 00 00 00 48 8b 94 24 a8 00 00 00 48 8b 9c 24 b0 00 00 00 48 8b b4 24 c0 00 00 00 48 8b bc 24 88 00 00 00 4c 8b 44 24 78 4c 8b 4c 24 68 4c 8b 94 24 80 00 00 00 48 89 d3 48 89 c6 48 89 cf 4c 8b 84 24 b0 00 00 00 4c 8b 8c 24 c0 00 00 00 4c 89 d0 48 8b 4c 24 68 48 8b 54 24 78 4c 8b 94 24 88 00 00 00 48 39 f8}  //weight: 1, accuracy: High
        $x_1_3 = "main.hasSuffix" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_AC_2147937876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.AC!MTB"
        threat_id = "2147937876"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.esxi_encoder" ascii //weight: 1
        $x_1_2 = "main.local_drop_note" ascii //weight: 1
        $x_1_3 = "main.progress_logger" ascii //weight: 1
        $x_1_4 = "main.is_exclude_dir" ascii //weight: 1
        $x_1_5 = "main.scan_ip" ascii //weight: 1
        $x_1_6 = "main.remote_init" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_AD_2147942311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.AD!MTB"
        threat_id = "2147942311"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 41 57 41 56 41 55 41 54 53 50 48 89 fb 48 8b 77 08 48 85 f6 74 12 48 8b 3b 48 c1 e6 04 ba 08 00 00 00 ff 15 27 90 0b 00 4c 8b 73 18 4c 8b 6b 28 49 ff c5 4c 89 f7}  //weight: 1, accuracy: High
        $x_1_2 = {48 89 fb 48 8b 0f 48 8b 7f 08 48 89 f8 48 29 c8 48 be ab aa aa aa aa aa aa aa 48 f7 e6 48 8d 05 83 6f fc ff 48 89 03 48 89 43 08 4c 8b 7b 10 48 39 cf 74 54 49 89 d6 49 c1 ee 04 49 8b 3f 48 29 f9 48 89 c8 48 f7 e6 48 c1 ea 04 48 8d 04 52 4c 8d 24 c7 49 83 c4 08 4c 8b 2d e9 c7 0b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Linux_Filecoder_AE_2147951874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Filecoder.AE!MTB"
        threat_id = "2147951874"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Filecoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {be 47 bb 40 00 31 c0 bf d8 b9 40 00 e8 44 1d 00 00 0f b6 3d fd f6 20 00 e8 88 42 00 00 bf 18 00 00 00 48 89 05 3c f7 20 00 e8 57 fa ff ff 4c 89 ef 48 89 c3 e8 4c fc ff ff 48 89 03 48 8b 05 12 f7 20 00 48 c7 43 08 00 00 00 00 48 89 43 10 48 89 18 48 83 c3 08 48 8b 05 90 f6 20 00 48 89 1d f1 f6 20 00 48 85 c0}  //weight: 1, accuracy: High
        $x_1_2 = {31 c0 be 59 bb 40 00 bf d8 b9 40 00 e8 44 1c 00 00 be 92 ba 40 00 bf 66 bb 40 00 e8 75 f9 ff ff 48 85 c0 48 89 c3 74 ae 80 3d 56 f5 20 00 00 75 a5 0f b7 15 ad f5 20 00 48 8b 3d 9e f5 20 00 48 89 c1 be 01 00 00 00 e8 79 fc ff ff 48 89 df e8 f1 fb ff ff eb 80 be e8 03 00 00 bf 01 00 00 00 45 31 ed}  //weight: 1, accuracy: High
        $x_1_3 = {48 89 ea 44 89 e6 bf a0 15 61 00 66 89 05 ce f7 20 00 e8 19 39 00 00 80 3d c4 f7 20 00 00 0f 85 2d 02 00 00 bf a0 15 61 00 e8 a2 20 00 00 48 8b 7d 00 be 2f 00 00 00 e8 74 fc ff ff 4c 8d 68 01 bf 19 bb 40 00 31 c0 4c 89 ee e8 31 24 00 00 31 c0 bf 2a bb 40 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

