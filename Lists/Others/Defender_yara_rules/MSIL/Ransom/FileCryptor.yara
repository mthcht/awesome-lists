rule Ransom_MSIL_FileCryptor_A_2147731393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.A!MTB"
        threat_id = "2147731393"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 20 7c 0c 00 00 28 e4 00 00 06 28 03 00 00 06 39 a5 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {45 06 00 00 00 12 00 00 00 cb ff ff ff 00 00 00 00 bb ff ff ff cb ff ff ff 2d 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = "$282b8d86-f33f-441e-8bb5-95903351be39" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_A_2147731393_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.A!MTB"
        threat_id = "2147731393"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "WHY YOU OPENED THE FUCKING FILE" wide //weight: 1
        $x_1_2 = ".txt.html.db.exe.jpg.png.gif.dll" wide //weight: 1
        $x_1_3 = "parseAndEncrypt" ascii //weight: 1
        $x_1_4 = "filesToEncrypt" ascii //weight: 1
        $x_1_5 = "PAYMENT ADDRESS:" wide //weight: 1
        $x_1_6 = "It seems like your files have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_A_2147731393_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.A!MTB"
        threat_id = "2147731393"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft\\delete_program.del" wide //weight: 1
        $x_1_2 = ".crypt" wide //weight: 1
        $x_1_3 = "ProcessHacker" wide //weight: 1
        $x_1_4 = "USBNAME" wide //weight: 1
        $x_1_5 = "/C choice /C Y /N /D Y /T 3 & Del \"" wide //weight: 1
        $x_1_6 = "Hi! your important files were encrypted!" wide //weight: 1
        $x_1_7 = "USBSPREAD" wide //weight: 1
        $x_1_8 = "\\WindowsKeyboardDriver.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_AA_2147748456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.AA!MTB"
        threat_id = "2147748456"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 00 69 00 73 00 74 00 65 00 6d 00 69 00 6e 00 69 00 7a 00 64 00 65 00 20 00 f6 00 6e 00 65 00 6d 00 6c 00 69 00 20 00 67 00 f6 00 72 00 64 00 fc 00 67 00 fc 00 6d 00 fc 00 7a 00 20 00 64 00 61 00 74 00 61 00 6c 00 61 00 72 00 69 00 6e 00 69 00 7a 00 69 00 20 00 73 00 69 00 66 00 72 00 65 00 6c 00 65 00 64 00 69 00 6b 00 2e 00}  //weight: 1, accuracy: High
        $x_1_2 = "DecryptRJ256" ascii //weight: 1
        $x_1_3 = "@decryptservice" wide //weight: 1
        $x_1_4 = "\\haci.dll" wide //weight: 1
        $x_1_5 = "\\README_DONT_DELETE.txt" wide //weight: 1
        $x_1_6 = "Java Embeded Library" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_B_2147750089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.B!MTB"
        threat_id = "2147750089"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\ByteLocker" wide //weight: 1
        $x_1_2 = "EncryptFolder" ascii //weight: 1
        $x_1_3 = "$recycle.bin" wide //weight: 1
        $x_1_4 = ".bytcrypttmp" wide //weight: 1
        $x_1_5 = "CurrentFileDecrypt" wide //weight: 1
        $x_1_6 = "Your personal files are encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_D_2147753081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.D!MTB"
        threat_id = "2147753081"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "locker" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" wide //weight: 1
        $x_1_3 = "lol.encrypt" wide //weight: 1
        $x_1_4 = "Your files has been encrypted" wide //weight: 1
        $x_1_5 = "EncryptedFileHeader" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_E_2147753088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.E!MTB"
        threat_id = "2147753088"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "L0MgdnNzYWRtaW4uZXhlIGRlbGV0ZSBzaGFkb3dzIC9hbGwgL1F1aWV0" wide //weight: 1
        $x_1_2 = "L0MgV01JQy5leGUgc2hhZG93Y29weSBkZWxldGUg" wide //weight: 1
        $x_1_3 = "\\DECRYPT_FILES.txt" wide //weight: 1
        $x_1_4 = "avpsus" wide //weight: 1
        $x_1_5 = "del selfd.bat" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_DSA_2147761224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.DSA!MTB"
        threat_id = "2147761224"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "taskkill /f /im explorer.exe" ascii //weight: 2
        $x_1_2 = "CoronaCrypt0r" ascii //weight: 1
        $x_1_3 = "Cobra_Locker" ascii //weight: 1
        $x_1_4 = "I have encrypted all your important files" ascii //weight: 1
        $x_1_5 = "There is no way to recover your files sorry" ascii //weight: 1
        $x_1_6 = "Cobra_Locker_Is_The_Best" ascii //weight: 1
        $x_1_7 = "all your important files have been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCryptor_T_2147767058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.T!MTB"
        threat_id = "2147767058"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".enc" ascii //weight: 1
        $x_1_2 = "Krypta Decrypted" ascii //weight: 1
        $x_1_3 = "\\Startup\\win32.exe" ascii //weight: 1
        $x_1_4 = "All files have been decrypted" ascii //weight: 1
        $x_1_5 = "Ransome" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_FileCryptor_S_2147767245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.S!MTB"
        threat_id = "2147767245"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Malware" ascii //weight: 1
        $x_1_2 = "we stole all your fileZ and ENCRYTPED THEM" ascii //weight: 1
        $x_1_3 = "This is not your lucky day!!" ascii //weight: 1
        $x_1_4 = ".encrypted" ascii //weight: 1
        $x_1_5 = ".xlsx" ascii //weight: 1
        $x_1_6 = ".pptx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_FileCryptor_PA_2147768398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PA!MTB"
        threat_id = "2147768398"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "fileEncrypted" ascii //weight: 1
        $x_1_2 = "OFF_Encrypt" ascii //weight: 1
        $x_1_3 = "img_56694" wide //weight: 1
        $x_1_4 = "UNLOCKED" wide //weight: 1
        $x_1_5 = "\\desktop.ini" wide //weight: 1
        $x_1_6 = "Ransomware2.0" wide //weight: 1
        $x_10_7 = {5c 52 61 6e 73 6f 6d 77 61 72 65 [0-6] 5c [0-16] 5c [0-16] 5c 52 61 6e 73 6f 6d 77 61 72 65 32 2e 30 2e 70 64 62}  //weight: 10, accuracy: Low
        $x_10_8 = {5c 52 61 73 6f 6d 77 61 72 65 [0-6] 5c [0-16] 5c [0-16] 5c 52 61 73 6f 6d 77 61 72 65 32 2e 30 2e 70 64 62}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCryptor_U_2147769160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.U!MTB"
        threat_id = "2147769160"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "virus" ascii //weight: 1
        $x_1_2 = "fileEncrypted" ascii //weight: 1
        $x_1_3 = "encrypte_decrypte_Function" ascii //weight: 1
        $x_1_4 = "\\endn_log.exe" ascii //weight: 1
        $x_1_5 = "bytesToEncrypted" ascii //weight: 1
        $x_1_6 = "C:\\r2block_Wallpaper.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_FileCryptor_PD_2147769383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PD!MTB"
        threat_id = "2147769383"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".TRUMP" wide //weight: 1
        $x_1_2 = "Decrypt Your PC" wide //weight: 1
        $x_1_3 = "You Have Been Fucked Mate" wide //weight: 1
        $x_1_4 = "Go Fuck Yourself" wide //weight: 1
        $x_1_5 = "Hello User all your files have been encrypted by Donald J. Trump" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_FileCryptor_PF_2147769479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PF!MTB"
        threat_id = "2147769479"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BitDecoder" ascii //weight: 1
        $x_1_2 = "DecodeWithMatchByte" ascii //weight: 1
        $x_1_3 = "$be27509a-c11b-4314-b02c-6355d52ace8a" ascii //weight: 1
        $x_1_4 = "CRYPT.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_V_2147770227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.V!MTB"
        threat_id = "2147770227"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted by CryRansomware!" ascii //weight: 1
        $x_1_2 = "Never open random files. This is your warning" ascii //weight: 1
        $x_1_3 = "IsTargetFile" ascii //weight: 1
        $x_1_4 = "encThread" ascii //weight: 1
        $x_1_5 = "get_FileChecker" ascii //weight: 1
        $x_1_6 = "EncryptBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_FileCryptor_PH_2147771454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PH!MTB"
        threat_id = "2147771454"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locked" wide //weight: 1
        $x_1_2 = "All File Is Encrypted" wide //weight: 1
        $x_1_3 = "ReadMe.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PG_2147771638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PG!MTB"
        threat_id = "2147771638"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".xxx" wide //weight: 1
        $x_1_2 = "\\Desktop\\readme.txt" wide //weight: 1
        $x_1_3 = "Files have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PG_2147771638_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PG!MTB"
        threat_id = "2147771638"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<Ransom_Note_Load>b" ascii //weight: 1
        $x_1_2 = "do not restart your computer or else it is destroyed!!!!!!!!!!!!!" wide //weight: 1
        $x_1_3 = "DisableTaskmgr" wide //weight: 1
        $x_1_4 = "your files are encrypted!" ascii //weight: 1
        $x_1_5 = "InstantRansom@" wide //weight: 1
        $x_1_6 = "Instant Ransomware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_FileCryptor_PL_2147771824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PL!MTB"
        threat_id = "2147771824"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Povlsomware" ascii //weight: 1
        $x_1_2 = "Win32_ShadowCopy" wide //weight: 1
        $x_1_3 = "Encrypted:" wide //weight: 1
        $x_1_4 = "Povlsomware.Properties.Resources" wide //weight: 1
        $x_1_5 = "\\Dotfuscated\\love.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PJ_2147771972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PJ!MTB"
        threat_id = "2147771972"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "45-512_35182" wide //weight: 1
        $x_1_2 = ".jgy" wide //weight: 1
        $x_1_3 = "JGY.exe" wide //weight: 1
        $x_1_4 = "UH-OH! YOUR FILES HAVE BEEN TAKEN OVER!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PJ_2147771972_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PJ!MTB"
        threat_id = "2147771972"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ReadMe_ransom.txt" wide //weight: 1
        $x_1_2 = ".neptunep" wide //weight: 1
        $x_1_3 = "! Cynet Ransom Protection(DON'T DELETE)" wide //weight: 1
        $x_1_4 = "\\Neptune_remote.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_MK_2147780034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.MK!MTB"
        threat_id = "2147780034"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "All of your files have been encrypted" ascii //weight: 10
        $x_10_2 = "No files to encrypt" ascii //weight: 10
        $x_2_3 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 [0-16] 53 00 68 00 65 00 6c 00 6c 00 [0-16] 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_2_4 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 57 69 6e 6c 6f 67 6f 6e [0-16] 53 68 65 6c 6c [0-16] 65 78 70 6c 6f 72 65 72 2e 65 78 65}  //weight: 2, accuracy: Low
        $x_2_5 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-16] 52 00 61 00 6e 00 73 00 6f 00 6d 00}  //weight: 2, accuracy: Low
        $x_2_6 = {53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e [0-16] 52 61 6e 73 6f 6d}  //weight: 2, accuracy: Low
        $x_2_7 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 [0-16] 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 41 00 6e 00 74 00 69 00 53 00 70 00 79 00 77 00 61 00 72 00 65 00 [0-16] 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 6f 00 75 00 74 00 69 00 6e 00 65 00 6c 00 79 00 54 00 61 00 6b 00 69 00 6e 00 67 00 41 00 63 00 74 00 69 00 6f 00 6e 00}  //weight: 2, accuracy: Low
        $x_2_8 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 [0-16] 44 69 73 61 62 6c 65 41 6e 74 69 53 70 79 77 61 72 65 [0-16] 44 69 73 61 62 6c 65 52 6f 75 74 69 6e 65 6c 79 54 61 6b 69 6e 67 41 63 74 69 6f 6e}  //weight: 2, accuracy: Low
        $x_2_9 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 4e 00 54 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 52 00 65 00 73 00 74 00 6f 00 72 00 65 00 73 00 [0-16] 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 53 00 52 00 [0-16] 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 43 00 6f 00 6e 00 66 00 69 00 67 00}  //weight: 2, accuracy: Low
        $x_2_10 = {53 6f 66 74 77 61 72 65 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 53 79 73 74 65 6d 52 65 73 74 6f 72 65 73 [0-16] 44 69 73 61 62 6c 65 53 52 [0-16] 44 69 73 61 62 6c 65 43 6f 6e 66 69 67}  //weight: 2, accuracy: Low
        $x_2_11 = {53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 66 00 65 00 6e 00 64 00 65 00 72 00 5c 00 52 00 65 00 61 00 6c 00 2d 00 54 00 69 00 6d 00 65 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 69 00 6f 00 6e 00 [0-16] 44 00 69 00 73 00 61 00 62 00 6c 00 65 00 52 00 65 00 61 00 6c 00 74 00 69 00 6d 00 65 00 4d 00 6f 00 6e 00 69 00 74 00 6f 00 72 00 69 00 6e 00 67 00}  //weight: 2, accuracy: Low
        $x_2_12 = {53 4f 46 54 57 41 52 45 5c 50 6f 6c 69 63 69 65 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 44 65 66 65 6e 64 65 72 5c 52 65 61 6c 2d 54 69 6d 65 20 50 72 6f 74 65 63 74 69 6f 6e [0-16] 44 69 73 61 62 6c 65 52 65 61 6c 74 69 6d 65 4d 6f 6e 69 74 6f 72 69 6e 67}  //weight: 2, accuracy: Low
        $x_1_13 = ".kfuald" ascii //weight: 1
        $x_10_14 = "Encrypting:" ascii //weight: 10
        $x_10_15 = "Oops... Your computer has been locked" ascii //weight: 10
        $x_1_16 = "Ransom.Properties.Resources" ascii //weight: 1
        $x_10_17 = "Annabelle-tear" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 9 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_10_*) and 10 of ($x_2_*))) or
            ((4 of ($x_10_*) and 4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_10_*) and 5 of ($x_2_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCryptor_PAD_2147781566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PAD!MTB"
        threat_id = "2147781566"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "all your personal files" ascii //weight: 1
        $x_1_2 = "ransomware" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" wide //weight: 1
        $x_1_4 = "C:\\Windows\\System32\\drivers\\disk.sys" wide //weight: 1
        $x_1_5 = "Incorrect key" wide //weight: 1
        $x_1_6 = "Processhacker" wide //weight: 1
        $x_1_7 = "shutdown" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_MAK_2147796922_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.MAK!MTB"
        threat_id = "2147796922"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Ransomware" ascii //weight: 1
        $x_1_2 = {50 00 61 00 79 00 20 00 77 00 69 00 74 00 68 00 20 00 [0-16] 20 00 42 00 54 00 43 00}  //weight: 1, accuracy: Low
        $x_1_3 = {50 61 79 20 77 69 74 68 20 [0-16] 20 42 54 43}  //weight: 1, accuracy: Low
        $x_1_4 = "You have to pay us with Bitcoin" ascii //weight: 1
        $x_1_5 = "If you think you can decrypt your files with yourself, so do it" ascii //weight: 1
        $x_1_6 = "encrypted using AES" ascii //weight: 1
        $x_1_7 = "Your Files has been encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_FileCryptor_MAK_2147796922_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.MAK!MTB"
        threat_id = "2147796922"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your files have been locked" ascii //weight: 1
        $x_1_2 = "Your files may only be restored by entering the correct password" ascii //weight: 1
        $x_1_3 = {41 00 6c 00 6c 00 20 00 66 00 69 00 6c 00 65 00 73 00 20 00 77 00 69 00 6c 00 6c 00 20 00 62 00 65 00 20 00 6c 00 65 00 61 00 6b 00 65 00 64 00 20 00 61 00 66 00 74 00 65 00 72 00 20 00 [0-5] 20 00 68 00 6f 00 75 00 72 00 73 00}  //weight: 1, accuracy: Low
        $x_1_4 = {41 6c 6c 20 66 69 6c 65 73 20 77 69 6c 6c 20 62 65 20 6c 65 61 6b 65 64 20 61 66 74 65 72 20 [0-5] 20 68 6f 75 72 73}  //weight: 1, accuracy: Low
        $x_1_5 = "HKEY_CURRENT_USER\\SOFTWARE\\Rnz" ascii //weight: 1
        $x_1_6 = "Restore my files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_FileCryptor_PB_2147799260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PB!MTB"
        threat_id = "2147799260"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".LOCK2G" wide //weight: 1
        $x_1_2 = "delete shadows /all /quiet" wide //weight: 1
        $x_1_3 = "have been encrypted on this PC" wide //weight: 1
        $x_1_4 = "\\!!!Recovery File.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PC_2147799361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PC!MTB"
        threat_id = "2147799361"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ATTENTION!!!.txt" wide //weight: 1
        $x_1_2 = "The terrible virus has captured your files" wide //weight: 1
        $x_1_3 = "\\RunAsDll.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PM_2147810217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PM!MTB"
        threat_id = "2147810217"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\RECUPERAR__ARQUIVOS/.covcrypt.txt" wide //weight: 1
        $x_1_2 = "have been encrypted!" wide //weight: 1
        $x_1_3 = ".covcrypt" wide //weight: 1
        $x_1_4 = "\\matshure.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PN_2147810297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PN!MTB"
        threat_id = "2147810297"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".gesh" wide //weight: 1
        $x_1_2 = "\\Recover Files.gesh.txt" wide //weight: 1
        $x_1_3 = "Ooops, your files have been encrypted!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PO_2147810304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PO!MTB"
        threat_id = "2147810304"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Microsoft\\Crypto\\Keys\\@WD30@.txt" wide //weight: 1
        $x_1_2 = "Your important files are encrypted." wide //weight: 1
        $x_1_3 = "\\WD30.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PP_2147810617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PP!MTB"
        threat_id = "2147810617"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\read_it.txt" wide //weight: 1
        $x_1_2 = "All your files have been encrypted with Ransomware virus" wide //weight: 1
        $x_1_3 = "PollyHjackingGroup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_PS_2147817058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.PS!MTB"
        threat_id = "2147817058"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all" wide //weight: 1
        $x_1_2 = "READ_ME.html" wide //weight: 1
        $x_1_3 = ".locked" wide //weight: 1
        $x_1_4 = "I am so sorry ! All your files have been encryptd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_AYA_2147957309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.AYA!MTB"
        threat_id = "2147957309"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "VELOX RANSOMWARE" wide //weight: 5
        $x_2_2 = "YOUR COMPUTER HAS BEEN LOCKED BY VELOX" wide //weight: 2
        $x_1_3 = "Your files have been decrypted." wide //weight: 1
        $x_1_4 = "veloxv.Properties.Resources" wide //weight: 1
        $x_1_5 = "EncryptFolder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCryptor_AYB_2147959754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCryptor.AYB!MTB"
        threat_id = "2147959754"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {07 09 9a 28 26 00 00 0a 13 04 06 11 04 6f 27 00 00 0a 28 01 00 00 2b 2c 0d 07 09 9a 7e 01 00 00 04 28 02 00 00 06 09 17 58 0d 09 07 8e 69 32 d0}  //weight: 7, accuracy: High
        $x_3_2 = "$74871748-d0a1-4faf-9e0a-912a4a32bda6" ascii //weight: 3
        $x_1_3 = "EncryptFolder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

