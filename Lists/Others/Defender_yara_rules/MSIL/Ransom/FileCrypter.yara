rule Ransom_MSIL_FileCrypter_MK_2147762086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCrypter.MK!MTB"
        threat_id = "2147762086"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomBlox.exe" ascii //weight: 1
        $x_1_2 = "RansomBlox.Properties" ascii //weight: 1
        $x_1_3 = "jaemin1508" ascii //weight: 1
        $x_1_4 = "$83a98c11-59b8-4cb5-8163-bcb9560c9c70" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCrypter_MK_2147762086_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCrypter.MK!MTB"
        threat_id = "2147762086"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomeware" ascii //weight: 1
        $x_1_2 = "hackermtc2k@india.com" ascii //weight: 1
        $x_1_3 = "Your file has been encrypted" ascii //weight: 1
        $x_1_4 = "You only have about 2 days to send money (500K) or your file will be lost" ascii //weight: 1
        $x_1_5 = "WanaCry Fake.ini" ascii //weight: 1
        $x_1_6 = "https://ylhsakxusnjablzqytnsdmrrpt0.000webhostapp.com/ramsom.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Ransom_MSIL_FileCrypter_MK_2147762086_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCrypter.MK!MTB"
        threat_id = "2147762086"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "payload" ascii //weight: 1
        $x_1_2 = "WTS_CURRENT_SERVER_HANDLE" ascii //weight: 1
        $x_1_3 = "WTSQuerySessionInformationW" ascii //weight: 1
        $x_1_4 = "SelfDestroy" ascii //weight: 1
        $x_1_5 = "SessionId" ascii //weight: 1
        $x_1_6 = "Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
        $x_1_7 = "\\svchost.exe" ascii //weight: 1
        $x_1_8 = "TASKKILL /F /IM" ascii //weight: 1
        $x_1_9 = "/C killme.bat >> NUL" ascii //weight: 1
        $x_1_10 = "bot_token=" ascii //weight: 1
        $x_1_11 = "Malware Excuted" ascii //weight: 1
        $x_1_12 = ".AMJIXIUS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Ransom_MSIL_FileCrypter_MK_2147762086_3
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCrypter.MK!MTB"
        threat_id = "2147762086"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "batch.bat" ascii //weight: 1
        $x_1_2 = ".z3back" ascii //weight: 1
        $x_1_3 = "Decrypted:" ascii //weight: 1
        $x_1_4 = ".z3enc" ascii //weight: 1
        $x_1_5 = "\\Desktop\\Sandbox" ascii //weight: 1
        $x_1_6 = "Oops! Your files have been encrypted!" ascii //weight: 1
        $x_1_7 = "If you close this window, all your data will be lost" ascii //weight: 1
        $x_1_8 = "\\key.txt" ascii //weight: 1
        $x_1_9 = "\\iv.txt" ascii //weight: 1
        $x_1_10 = "Currently you can decrypt 10 file" ascii //weight: 1
        $x_1_11 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCrypter_MK_2147762086_4
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCrypter.MK!MTB"
        threat_id = "2147762086"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_readme.txt" ascii //weight: 1
        $x_1_2 = "All your files like photos, database, documents and other importatnt are encrypted with strongest encryption and unique key" ascii //weight: 1
        $x_1_3 = "This software will decrypt all your encrypted files" ascii //weight: 1
        $x_1_4 = "we can decrypt only 1 file free" ascii //weight: 1
        $x_1_5 = "Price of private key and decrypt software is 7800$" ascii //weight: 1
        $x_1_6 = "Your Personal ID:" ascii //weight: 1
        $x_1_7 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCrypter_NB_2147765546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCrypter.NB!MTB"
        threat_id = "2147765546"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hacker2" ascii //weight: 1
        $x_1_2 = "you are encrypted with powerful military grade Ransomware/Doxware" ascii //weight: 1
        $x_1_3 = "pay us $4.5 Million of Bitcoin within 52 hours" ascii //weight: 1
        $x_1_4 = "YOUR REPUTATION WILL BE OVER" ascii //weight: 1
        $x_1_5 = ".Nibiru" ascii //weight: 1
        $x_1_6 = "YOU HAVE BEEN HACKED" ascii //weight: 1
        $x_1_7 = "All Your Files Transfered To Hackers Remote Server" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCrypter_MA_2147766792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCrypter.MA!MTB"
        threat_id = "2147766792"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Rasomware2.0" ascii //weight: 1
        $x_1_2 = "Ransomware2_Load" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "minegames321" wide //weight: 1
        $x_1_5 = "All your Files Encrypted with Ahmed minegames Ransomware" wide //weight: 1
        $x_1_6 = "your files,photos,exe files, all of them encrypted" wide //weight: 1
        $x_1_7 = "Rasomware2._0.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCrypter_ABS_2147827395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCrypter.ABS!MTB"
        threat_id = "2147827395"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 08 11 04 9a 28 05 ?? ?? 06 08 11 04 9a 72 75 ?? ?? 70 28 43 ?? ?? 0a 28 44 ?? ?? 0a 11 04 17 58 13 04 11 04 08 8e 69 32 d6}  //weight: 2, accuracy: Low
        $x_2_2 = {06 07 28 02 ?? ?? 06 0c 03 08 28 2d ?? ?? 0a 03 28 2e ?? ?? 0a 0d 03 16 03 39 00 03 28 28 ?? ?? 0a 0a 28 29 ?? ?? 0a 04 6f 2a ?? ?? 0a 0b 28 2b ?? ?? 0a 07 6f 2c ?? ?? 0a 0b 02}  //weight: 2, accuracy: Low
        $x_1_3 = "bytesToBeDecrypted" ascii //weight: 1
        $x_1_4 = "CipherMode" ascii //weight: 1
        $x_1_5 = "DecryptFile" ascii //weight: 1
        $x_1_6 = "GetExtension" ascii //weight: 1
        $x_1_7 = "GetDirectories" ascii //weight: 1
        $x_1_8 = "passwordBytes" ascii //weight: 1
        $x_1_9 = "ReadAllBytes" ascii //weight: 1
        $x_1_10 = "DecryptDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCrypter_MBCT_2147846570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCrypter.MBCT!MTB"
        threat_id = "2147846570"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0d 11 0e 9a 13 0f 00 00 07 11 0f 11 0f 72 1f 00 00 70}  //weight: 1, accuracy: High
        $x_1_2 = "d5a01s9u" wide //weight: 1
        $x_1_3 = "RANSOMWARE3._0" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

