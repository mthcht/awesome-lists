rule Ransom_Win32_FileCryptor_G_2147753632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.G!MTB"
        threat_id = "2147753632"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 63 6f 64 65 72 3a 20 25 73 [0-32] 25 73 2e 6c 6f 63 6b}  //weight: 1, accuracy: Low
        $x_1_2 = {45 6e 63 6f 64 65 72 20 [0-32] 20 53 74 61 72 74}  //weight: 1, accuracy: Low
        $x_1_3 = "FindFirstFileA" ascii //weight: 1
        $x_1_4 = {44 6f 63 75 6d 65 6e 74 73 20 61 6e 64 20 53 65 74 74 69 6e 67 73 [0-48] 65 6d 70 74 79 2e 6c 6f 63 6b}  //weight: 1, accuracy: Low
        $x_1_5 = "TouchMeNot_.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_H_2147755292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.H!MTB"
        threat_id = "2147755292"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".data_encrypted" wide //weight: 1
        $x_1_2 = ".passwd" wide //weight: 1
        $x_1_3 = {2e 00 64 00 6f 00 63 00 [0-16] 2e 00 64 00 6f 00 63 00 78 00 [0-16] 2e 00 78 00 6c 00 73 00 [0-16] 2e 00 78 00 6c 00 73 00 78 00}  //weight: 1, accuracy: Low
        $x_1_4 = "passwordBytes" ascii //weight: 1
        $x_1_5 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_6 = "bitcoin" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_I_2147758457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.I!MTB"
        threat_id = "2147758457"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Mz5Pb3BzLCB5b3VyIHBlcnNvbmFsIGZpbGVzIGhhdmUgYmVlbiBlbmNyeXB0ZWQhPC9oMz" wide //weight: 1
        $x_1_2 = "PGgzPk9vcHMsIHlvdXIgZmlsZXMgYXJlIGVuY3J5cHRlZCEhITwvaDM+" wide //weight: 1
        $x_1_3 = "Read me!" wide //weight: 1
        $x_1_4 = "Read-me!" wide //weight: 1
        $x_1_5 = {2e 00 70 00 64 00 66 00 [0-16] 2e 00 7a 00 69 00 70 00 [0-16] 2e 00 70 00 70 00 74 00 [0-16] 2e 00 64 00 6f 00 63 00}  //weight: 1, accuracy: Low
        $x_1_6 = "EncryptBytes" ascii //weight: 1
        $x_1_7 = "get_TargetFiles" ascii //weight: 1
        $x_1_8 = "GetEncryptionThreads" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_FileCryptor_J_2147759077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.J!MTB"
        threat_id = "2147759077"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptData" ascii //weight: 1
        $x_1_2 = "get_payload" ascii //weight: 1
        $x_1_3 = "taskkill /f /im taskmgr.exe" ascii //weight: 1
        $x_1_4 = "wmic useraccount where name='%username%' rename 'IT'" ascii //weight: 1
        $x_1_5 = "del /f /s /q %userprofile%\\Desktop\\" ascii //weight: 1
        $x_1_6 = "del /f /s /q \"C:\\Program Files\\WindowsApps" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_K_2147759661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.K!MTB"
        threat_id = "2147759661"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encrypted by BlackRabbit." ascii //weight: 1
        $x_1_2 = "how_to_decrypt.hta" ascii //weight: 1
        $x_1_3 = "Encrypt all" ascii //weight: 1
        $x_1_4 = "Encrypted files:" ascii //weight: 1
        $x_1_5 = "ods,xar,xlr,xls,xlsb,xlsm,xlsx,xlt,xltm,xltx,asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_M_2147761155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.M!MTB"
        threat_id = "2147761155"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "decrypt files, you need to pay" ascii //weight: 1
        $x_1_2 = "Your personal fIles are encrypted" ascii //weight: 1
        $x_1_3 = ".Lock" ascii //weight: 1
        $x_1_4 = "CryptoLocker" ascii //weight: 1
        $x_1_5 = "/c del C:\\* /s /q" ascii //weight: 1
        $x_1_6 = "Payment is accepted only in bitcoin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_FileCryptor_N_2147761990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.N!MTB"
        threat_id = "2147761990"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c del C:* /s /q" ascii //weight: 1
        $x_1_2 = "You Can't decrypt" ascii //weight: 1
        $x_1_3 = "Ransomnote" ascii //weight: 1
        $x_1_4 = "your files will be deleted forever" ascii //weight: 1
        $x_1_5 = "Reder_lock" ascii //weight: 1
        $x_1_6 = "/c taskkill /im explorer.exe /f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_FileCryptor_P_2147763575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.P!MTB"
        threat_id = "2147763575"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You Have Been Hacked" ascii //weight: 1
        $x_1_2 = "YOUR BITCOIN ADDRESS" ascii //weight: 1
        $x_1_3 = "Don't infect again" ascii //weight: 1
        $x_1_4 = "Desktop\\README.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_O_2147764344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.O!MTB"
        threat_id = "2147764344"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "HOW_TO_DECRYPT" ascii //weight: 1
        $x_1_2 = "@protonmail.com" ascii //weight: 1
        $x_1_3 = {54 00 68 00 65 00 20 00 [0-16] 20 00 69 00 73 00 20 00 4c 00 4f 00 43 00 4b 00 45 00 44 00}  //weight: 1, accuracy: Low
        $x_1_4 = {54 68 65 20 [0-16] 20 69 73 20 4c 4f 43 4b 45 44}  //weight: 1, accuracy: Low
        $x_1_5 = {44 00 6f 00 20 00 6e 00 6f 00 74 00 [0-32] 75 00 73 00 65 00 20 00 4f 00 54 00 48 00 45 00 52 00 20 00 73 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 6f 20 6e 6f 74 [0-32] 75 73 65 20 4f 54 48 45 52 20 73 6f 66 74 77 61 72 65}  //weight: 1, accuracy: Low
        $x_1_7 = {46 00 6f 00 72 00 20 00 44 00 45 00 43 00 52 00 59 00 50 00 54 00 [0-32] 20 00 77 00 72 00 69 00 74 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = {46 6f 72 20 44 45 43 52 59 50 54 [0-32] 20 77 72 69 74 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_FileCryptor_Q_2147764792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.Q!MTB"
        threat_id = "2147764792"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 43 50 83 ef 10 8b 55 fc 0f b7 4b 5a c1 e0 10 33 c8 33 0a 33 4b 44 89 0e 8b 43 58 0f b7 4b 62 c1 e0 10 33 c8 33 4a 04 33 4b 4c 89 4e 04 8b 43 60 0f b7 4b 4a c1 e0 10 33 c8 33 4a 08}  //weight: 1, accuracy: High
        $x_1_2 = {8b 7b 20 03 3b 0f b7 cf 8b d7 c1 ea 10 8b f1 0f af f1 8b c2 0f af c1 0f af d2 0f af ff c1 ee 11 03 f0 8b 45 f4 c1 ee 0f 03 f2 33 f7 83 6d fc 01 89 34 18 8d 5b 04 75 c8}  //weight: 1, accuracy: High
        $x_1_3 = {8d 4d e8 03 cf 8a 04 08 32 01 47 88 04 0a 8b 45 fc 3b fe 72 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_R_2147766837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.R!MTB"
        threat_id = "2147766837"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Processhacker" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "NO TRATES DE BORRAR EL RANSOMWARE" ascii //weight: 1
        $x_1_4 = "NO TRATES DE ABRIR ARCHIVOS ENCRYPTADOS" ascii //weight: 1
        $x_1_5 = "ESTE ARCHIVO ESTA MUY BIEN ENCRYPTADO NO TRATES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_FileCryptor_PC_2147768471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.PC!MTB"
        threat_id = "2147768471"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\README.txt" ascii //weight: 1
        $x_1_2 = "net user /add RedROMAN p4zzaub71h" ascii //weight: 1
        $x_1_3 = "\\Desktop\\ENTER-PASSWORD-HERE.txt" ascii //weight: 1
        $x_1_4 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_5 = "\\Start Menu\\Programs\\Startup\\README.html" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_Win32_FileCryptor_PB_2147771216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.PB!MTB"
        threat_id = "2147771216"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "lock.locked()" wide //weight: 1
        $x_1_2 = "FP_NO_HOST_CHECK=" ascii //weight: 1
        $x_1_3 = ".\\Cobalt-Client-log.txt" wide //weight: 1
        $x_1_4 = {5c 43 6f 62 61 6c 74 5c [0-16] 5c [0-16] 5c 43 6c 69 65 6e 74 5c 43 6f 62 61 6c 74 2e 43 6c 69 65 6e 74 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_PK_2147771782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.PK!MTB"
        threat_id = "2147771782"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILEWRITE ( $HFILE , \"Guardiran.org\" & @CRLF )" ascii //weight: 1
        $x_1_2 = "FILECRYPTOR ( $DRIVE [ $I ] & \"\\\" , \"*.doc\" )" ascii //weight: 1
        $x_1_3 = "$RANSOMWAREEXT = STRINGREPLACE ( $PATHTARGET & $FILEADDRESS , $CLEANFILETYPE , \".HaHaHaHaHaHaHaHa\" , 0 , 0 )" ascii //weight: 1
        $x_1_4 = "_CRYPT_ENCRYPTFILE ( $PATHTARGET & $FILEADDRESS , $RANSOMWAREEXT , $ENCKEY , $CALG_AES_256 )" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_W_2147772551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.W!MTB"
        threat_id = "2147772551"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\SOFTWARE\\Lucy" ascii //weight: 1
        $x_1_2 = {2a 00 2e 00 74 00 78 00 74 00 [0-47] 2a 00 2e 00 6f 00 64 00 74 00 [0-47] 2a 00 2e 00 77 00 70 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2a 2e 74 78 74 [0-47] 2a 2e 6f 64 74 [0-47] 2a 2e 77 70 73}  //weight: 1, accuracy: Low
        $x_1_4 = "Cryptolocker" ascii //weight: 1
        $x_1_5 = ".Encode" ascii //weight: 1
        $x_1_6 = "File.Lusy" ascii //weight: 1
        $x_1_7 = "DCPcrypt" ascii //weight: 1
        $x_1_8 = "DCPbase64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_Win32_FileCryptor_MK_2147773938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.MK!MTB"
        threat_id = "2147773938"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files has been encrypted" ascii //weight: 1
        $x_1_2 = "cryptormsg.hta" ascii //weight: 1
        $x_1_3 = "Pay 0.0002 BTC" ascii //weight: 1
        $x_1_4 = "If you don't want pay there's no problem" ascii //weight: 1
        $x_1_5 = "your files will be DESTROYED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_PAC_2147780152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.PAC!MTB"
        threat_id = "2147780152"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c1 e0 08 33 c7 bf ff 00 00 00 c1 e0 08 33 c3 c1 e0 08 33 45 fc 89 04 b5 90 b4 41 00 c1 c0 08 89 04 b5 90 b0 41 00 c1 c0 08 89 04 b5 90 c0 41 00 c1 c0 08 89 04 b5 68 a3 41 00 46 81 fe 00 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_PAB_2147783538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.PAB!MTB"
        threat_id = "2147783538"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nuR\\noisreVtnerruC\\swodniW\\tfosorciM\\erawtfoS" ascii //weight: 1
        $x_1_2 = "http://mail.rotblau.eu:15332/" ascii //weight: 1
        $x_1_3 = "C:\\INTERNAL\\REMOTE.EXE" ascii //weight: 1
        $x_1_4 = "Good Luck" ascii //weight: 1
        $x_1_5 = "UnhookWindowsHookEx" ascii //weight: 1
        $x_1_6 = "DerRosarotePanther&Freunde|Unsichtbarkeitsspray" ascii //weight: 1
        $x_1_7 = "tusrkheresoP" ascii //weight: 1
        $x_2_8 = {c6 45 fc 05 b9 ?? ?? ?? ?? 8b 75 e4 8b c6 66 0f 1f 44 00 00 66 8b 10 66 3b 11 75 1e 66 85 d2 74 15 66 8b 50 02 66 3b 51 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_FileCryptor_MA_2147808457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.MA!MTB"
        threat_id = "2147808457"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "23"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Shell.Run" ascii //weight: 1
        $x_1_2 = {6d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 73 00 74 00 61 00 72 00 74 00 20 00 6d 00 65 00 6e 00 75 00 5c 00 70 00 72 00 6f 00 67 00 72 00 61 00 6d 00 73 00 5c 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 5c 00 [0-10] 2e 00 76 00 62 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6d 69 63 72 6f 73 6f 66 74 5c 77 69 6e 64 6f 77 73 5c 73 74 61 72 74 20 6d 65 6e 75 5c 70 72 6f 67 72 61 6d 73 5c 73 74 61 72 74 75 70 5c [0-10] 2e 76 62 73}  //weight: 1, accuracy: Low
        $x_2_4 = "neco_arc.png" ascii //weight: 2
        $x_10_5 = "Ooops, You were been ransomwared :(" ascii //weight: 10
        $x_10_6 = "Your files are unrecoverable, good job cleaning!" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_FileCryptor_MAK_2147810020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.MAK!MTB"
        threat_id = "2147810020"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "documents on your computer are encrypted" ascii //weight: 1
        $x_1_2 = "HOW_FIX_FILES.htm" ascii //weight: 1
        $x_1_3 = "ransomware" ascii //weight: 1
        $x_1_4 = "Your Personal CODE:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_MAK_2147810020_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.MAK!MTB"
        threat_id = "2147810020"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".onion/gate.php" ascii //weight: 1
        $x_1_2 = "Your files are encrypted, and currently unavailable" ascii //weight: 1
        $x_1_3 = "you will lose your time and data" ascii //weight: 1
        $x_1_4 = "!!! DANGER !!!" ascii //weight: 1
        $x_1_5 = "\\\\.\\PhysicalDrive0" ascii //weight: 1
        $x_1_6 = "expand 32-byte k" ascii //weight: 1
        $x_1_7 = "encryptHDD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Ransom_Win32_FileCryptor_MBK_2147810021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.MBK!MTB"
        threat_id = "2147810021"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 10
        $x_10_2 = "WMIC.exe shadowcopy delete /nointeractive" ascii //weight: 10
        $x_10_3 = "bcdedit.exe /set {default} recoveryenabled No" ascii //weight: 10
        $x_10_4 = "bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures wbadmin DELETE SYSTEMSTATEBACKUP wbadmin DELETE" ascii //weight: 10
        $x_1_5 = "net stop BackupExecAgentAccelerator /y" ascii //weight: 1
        $x_1_6 = "net stop BackupExecAgentBrowser /y" ascii //weight: 1
        $x_1_7 = "net stop McAfeeEngineService /y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_FileCryptor_PT_2147817476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.PT!MTB"
        threat_id = "2147817476"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/c timeout 1 && del \"%s\"" wide //weight: 1
        $x_1_2 = "info.txt" wide //weight: 1
        $x_1_3 = "All your data been crypted!" wide //weight: 1
        $x_1_4 = "DamianOlsonsnowdrop@cock.li" wide //weight: 1
        $x_1_5 = {2e 00 73 00 63 00 72 00 [0-4] 2e 00 63 00 6d 00 64 00 [0-4] 2e 00 64 00 6c 00 6c 00 [0-4] 2e 00 62 00 61 00 74 00 [0-4] 2e 00 63 00 70 00 6c 00 [0-4] 2e 00 73 00 79 00 73 00 [0-4] 2e 00 6d 00 73 00 63 00 [0-4] 2e 00 63 00 6f 00 6d 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_PAHF_2147960435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.PAHF!MTB"
        threat_id = "2147960435"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "vssadmin delete shadows /all /quiet" ascii //weight: 2
        $x_1_2 = "bcdedit /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
        $x_1_4 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_5 = "DisableAntiVirus" ascii //weight: 1
        $x_2_6 = "YOUR FILES HAVE BEEN ENCRYPTED" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_FileCryptor_PAHG_2147960561_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FileCryptor.PAHG!MTB"
        threat_id = "2147960561"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FileCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your files have been encrypted" ascii //weight: 2
        $x_1_2 = "drivers\\etc\\hosts" ascii //weight: 1
        $x_1_3 = "READ_ME.txt" ascii //weight: 1
        $x_1_4 = "DO NOT RESTART YOUR COMPUTER" ascii //weight: 1
        $x_1_5 = "Your documents, photos, databases, and other files are no longer accessible" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

