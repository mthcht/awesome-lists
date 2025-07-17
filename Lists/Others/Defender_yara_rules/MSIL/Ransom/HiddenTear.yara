rule Ransom_MSIL_HiddenTear_A_2147723151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.A"
        threat_id = "2147723151"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Desktop\\README.txt" wide //weight: 1
        $x_1_2 = "https://viro.mleydier.fr/noauth" wide //weight: 1
        $x_1_3 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00 13 2f 00 63 00 20 00 73 00 74 00 61 00 72 00 74 00 20 00 00 03 5f 00 00 01 00 23 4b 00 65 00 79 00 4c 00 6f 00 67 00 67 00 65 00 72 00 20 00 53 00 74 00 61 00 72 00 74 00 65 00 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_A_2147723151_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.A"
        threat_id = "2147723151"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "#How_Decrypt_Files.txt" ascii //weight: 2
        $x_2_2 = "\\Desktop\\test\\READ_IT.txt" ascii //weight: 2
        $x_2_3 = "\\Desktop\\Hacked.txt" ascii //weight: 2
        $x_2_4 = "InfiniteDecryptor@Protonmail.com" ascii //weight: 2
        $x_2_5 = "1CCnFhbLT1VSMUqXaSqsYUAwcGU4evkbJo" ascii //weight: 2
        $x_2_6 = "blackgold123@protonmail.com" ascii //weight: 2
        $x_2_7 = "vnransomware@zoho.com" ascii //weight: 2
        $x_2_8 = "InfiniteTear" ascii //weight: 2
        $x_2_9 = "hidden_tear" ascii //weight: 2
        $x_2_10 = "hidden-tear" ascii //weight: 2
        $x_2_11 = "hidden tear" ascii //weight: 2
        $x_2_12 = "InfiniteInc 2017" ascii //weight: 2
        $x_2_13 = "Ransomware Ultimo" ascii //weight: 2
        $x_2_14 = "\"InfiniteTear Ransomware\"" ascii //weight: 2
        $x_2_15 = "\"Infinite Decryptor\"" ascii //weight: 2
        $x_2_16 = "\"Infinite Ransomware\"" ascii //weight: 2
        $x_2_17 = ".Infinite" ascii //weight: 2
        $x_2_18 = ".locked" ascii //weight: 2
        $x_2_19 = "All your important files, such as documents, images, videos, databases are encrypted" ascii //weight: 2
        $x_2_20 = "Oooopppsss Your Files Has Been Encrypted" ascii //weight: 2
        $x_1_21 = "vssadmin.exe delete shadows /all /Quiet" ascii //weight: 1
        $x_1_22 = "WMIC.exe shadowcopy delete" ascii //weight: 1
        $x_1_23 = "Bcdedit.exe /set {default} recoveryenabled no" ascii //weight: 1
        $x_1_24 = "Bcdedit.exe /set {default} bootstatuspolicy ignoreallfailures" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 4 of ($x_1_*))) or
            ((5 of ($x_2_*) and 2 of ($x_1_*))) or
            ((6 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_HiddenTear_B_2147731323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.B"
        threat_id = "2147731323"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Drpbx\\drpbx.exe" wide //weight: 1
        $x_1_2 = "Frfx\\firefox.exe" wide //weight: 1
        $x_1_3 = "\\DeleteItself.bat" wide //weight: 1
        $x_1_4 = "EncryptedFileList.txt" wide //weight: 1
        $x_1_5 = "ransomware.victims.itm.txt" wide //weight: 1
        $x_1_6 = "Locker.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_HiddenTear_C_2147731336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.C"
        threat_id = "2147731336"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your computer file is encrypted and can not be opened.It's no use looking at file extensions!" wide //weight: 1
        $x_1_2 = "\\obj\\Debug\\ScreenLocker.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_AA_2147752899_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.AA!MTB"
        threat_id = "2147752899"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EncryptedFilesList" ascii //weight: 1
        $x_1_2 = "Your files have been fucked" wide //weight: 1
        $x_1_3 = "recover your files, you have to pay" wide //weight: 1
        $x_1_4 = "Bytelocker" ascii //weight: 1
        $x_1_5 = "timeout 3 & del /f /q" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_TH_2147754741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.TH!MTB"
        threat_id = "2147754741"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Startup\\svchost.exe" wide //weight: 1
        $x_1_2 = "ZFIRE HAS INFECTED UR POOPHOLE" wide //weight: 1
        $x_1_3 = "Checking if you have payed." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Ransom_MSIL_HiddenTear_RN_2147759226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.RN!MTB"
        threat_id = "2147759226"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "LComputer code on a screen with a skull representing a computer virus / malware attack." ascii //weight: 5
        $x_1_2 = "EncryptOrDecryptFile" ascii //weight: 1
        $x_1_3 = "ActionEncrypt" ascii //weight: 1
        $x_1_4 = "ActionDecrypt" ascii //weight: 1
        $x_5_5 = "reha_ransomware_650x381" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_HiddenTear_ST_2147762468_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.ST!MTB"
        threat_id = "2147762468"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files has been encrypted by using secret encryption method" ascii //weight: 1
        $x_1_2 = "There is no easy method decrypting files unless you want to guess your key!" ascii //weight: 1
        $x_1_3 = "Your personal key for decryption:" ascii //weight: 1
        $x_1_4 = "If you are smart you know how to decrypt your files with this key." ascii //weight: 1
        $x_1_5 = "Key is wrong! Please restart the program to send it again." ascii //weight: 1
        $x_1_6 = "del /Q /F C:\\Program Files\\kasper" ascii //weight: 1
        $x_1_7 = "del /Q /F C:\\Program Files\\Norton" ascii //weight: 1
        $x_1_8 = "del /Q /F C:\\Program Files\\Mcafee" ascii //weight: 1
        $x_1_9 = "del /Q /F C:\\Program Files\\trojan" ascii //weight: 1
        $x_1_10 = "del /Q /F C:\\Program Files\\nood32" ascii //weight: 1
        $x_1_11 = "del /Q /F C:\\Program Files\\panda" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Ransom_MSIL_HiddenTear_DB_2147769566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DB!MTB"
        threat_id = "2147769566"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HiddenTear.Properties.Resources" ascii //weight: 1
        $x_1_2 = "RANSOM_NOTE.txt" ascii //weight: 1
        $x_1_3 = "/C vssadmin Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_4 = ".LOCKED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DC_2147772408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DC!MTB"
        threat_id = "2147772408"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe Delete Shadows /All /Quiet" ascii //weight: 1
        $x_1_2 = "DisableRealtimeMonitoring" ascii //weight: 1
        $x_1_3 = "DisableAntiSpyware" ascii //weight: 1
        $x_1_4 = ".encrypted11" ascii //weight: 1
        $x_1_5 = "@tutanota.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DD_2147772562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DD!MTB"
        threat_id = "2147772562"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_2 = "Your computer is infected with a virus" ascii //weight: 1
        $x_1_3 = "@tutanota.com" ascii //weight: 1
        $x_1_4 = ".info.hta" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DE_2147772856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DE!MTB"
        threat_id = "2147772856"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fileEncryptionrc4" ascii //weight: 1
        $x_1_2 = ".[neftet@tutanota.com].boom" ascii //weight: 1
        $x_1_3 = "READ_ME.hta" ascii //weight: 1
        $x_1_4 = "/C choice /C Y /N /D Y /T 1 & Del" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_MK_2147773004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.MK!MTB"
        threat_id = "2147773004"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CustomRC4" ascii //weight: 1
        $x_1_2 = "fileEncryptionrc4" ascii //weight: 1
        $x_1_3 = ".info.hta" ascii //weight: 1
        $x_1_4 = "payload" ascii //weight: 1
        $x_1_5 = "@tutanota.com" ascii //weight: 1
        $x_1_6 = "\\READ_ME.hta" ascii //weight: 1
        $x_1_7 = "do not try to rename encrypted files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DF_2147773120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DF!MTB"
        threat_id = "2147773120"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "your files have been encrypted" ascii //weight: 1
        $x_1_2 = ".Encrypted" ascii //weight: 1
        $x_1_3 = "@tutanota.com" ascii //weight: 1
        $x_1_4 = "recoveryenabled no" ascii //weight: 1
        $x_1_5 = "bootstatuspolicy ignoreallfailures" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DG_2147773121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DG!MTB"
        threat_id = "2147773121"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "important files that were encrypted" ascii //weight: 1
        $x_1_2 = "@protonmail.com" ascii //weight: 1
        $x_1_3 = "Important.txt" ascii //weight: 1
        $x_1_4 = "DarkWorld" ascii //weight: 1
        $x_1_5 = ".dark" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DI_2147773127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DI!MTB"
        threat_id = "2147773127"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES ARE ENCRYPTED" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows /All /Quiet" ascii //weight: 1
        $x_1_3 = "DECRYPT_ME_.TXT.locked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DJ_2147773177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DJ!MTB"
        threat_id = "2147773177"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encryption completed" ascii //weight: 1
        $x_1_2 = "HiddenTear" ascii //weight: 1
        $x_1_3 = ".locked" ascii //weight: 1
        $x_1_4 = "netsh firewall set opmode disable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DH_2147774378_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DH!MTB"
        threat_id = "2147774378"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\xxx\\source\\repos\\Launcher\\Launcher\\obj\\Debug\\BY.pdb" ascii //weight: 1
        $x_1_2 = "Launcher.Properties.Resources" ascii //weight: 1
        $x_1_3 = "/f /im BY.exe" ascii //weight: 1
        $x_1_4 = "get_BabaYaga" ascii //weight: 1
        $x_1_5 = "BabaYaga.exe" ascii //weight: 1
        $x_1_6 = "taskkill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DL_2147774384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DL!MTB"
        threat_id = "2147774384"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "DisableTaskMgr" ascii //weight: 10
        $x_1_2 = "Ransomware2.0" ascii //weight: 1
        $x_1_3 = "EncryptFile" ascii //weight: 1
        $x_1_4 = "ReadToRestore.txt" ascii //weight: 1
        $x_1_5 = "All your Files are Encrypted" ascii //weight: 1
        $x_1_6 = "Malware 2.0" ascii //weight: 1
        $x_1_7 = "Malware_2._0.Payloads" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_HiddenTear_DM_2147777157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DM!MTB"
        threat_id = "2147777157"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransom_Form" ascii //weight: 1
        $x_1_2 = "KeyLogger Started" ascii //weight: 1
        $x_1_3 = "botnet" ascii //weight: 1
        $x_1_4 = "Office Updater" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DN_2147778688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DN!MTB"
        threat_id = "2147778688"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your files have been encrypted" ascii //weight: 1
        $x_1_2 = "bitcoin" ascii //weight: 1
        $x_1_3 = ".locked" ascii //weight: 1
        $x_1_4 = "hidden_tear" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PB_2147779695_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PB!MTB"
        threat_id = "2147779695"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FILES ENCRYPTED.TXT" wide //weight: 1
        $x_1_2 = "All your files have been encrypted!" wide //weight: 1
        $x_1_3 = "FILES ENCRYPTED.bat" wide //weight: 1
        $x_1_4 = ".id-1E192D2A.[xmmh@tutanota.com].combo13" wide //weight: 1
        $x_1_5 = "\\IS_room_start.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_HiddenTear_DO_2147779982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DO!MTB"
        threat_id = "2147779982"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Your personal files have been encrypted" ascii //weight: 1
        $x_1_2 = "Bitcoin Address" ascii //weight: 1
        $x_1_3 = "ransom.jpg" ascii //weight: 1
        $x_1_4 = ".flyper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DP_2147780429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DP!MTB"
        threat_id = "2147780429"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hidden_tear2.exe" ascii //weight: 1
        $x_1_2 = "hidden_tear2.Properties" ascii //weight: 1
        $x_1_3 = "GetDirectories" ascii //weight: 1
        $x_1_4 = "GetExtension" ascii //weight: 1
        $x_1_5 = "GetFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PD_2147786694_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PD!MTB"
        threat_id = "2147786694"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "phenol@No-reply.com" wide //weight: 1
        $x_1_2 = "\\Desktop\\READ_IT.txt" wide //weight: 1
        $x_1_3 = "Your Files have been encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PE_2147787293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PE!MTB"
        threat_id = "2147787293"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all /Quiet" wide //weight: 1
        $x_1_2 = ".encrypted.contact_here_me@india.com.enjey" wide //weight: 1
        $x_1_3 = "\\README_DECRYPT.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PF_2147787728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PF!MTB"
        threat_id = "2147787728"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locked" wide //weight: 1
        $x_1_2 = "\\UNLOCK_FILES_INSTRUCTIONS.txt" wide //weight: 1
        $x_1_3 = "/c vssadmin delete shadows /all /quiet" wide //weight: 1
        $x_1_4 = "All your important files are encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_A_2147788487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.A!MTB"
        threat_id = "2147788487"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SUSPEITA DE RANSOMWARE" wide //weight: 1
        $x_1_2 = "msprotect.indicadoresms.com.br" wide //weight: 1
        $x_1_3 = "help24decrypt@qq.com" wide //weight: 1
        $x_1_4 = "ClopReadMe.txt" wide //weight: 1
        $x_1_5 = "HELP_BY_CROC.TXT" wide //weight: 1
        $x_1_6 = "INICIO.INI" wide //weight: 1
        $x_1_7 = "tentativa.log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_DQ_2147789180_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.DQ!MTB"
        threat_id = "2147789180"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MoonWare" ascii //weight: 1
        $x_1_2 = "0.5 bitcons | Address:" ascii //weight: 1
        $x_1_3 = "filesToEncrpyt" ascii //weight: 1
        $x_1_4 = "parseAndEncrypt" ascii //weight: 1
        $x_1_5 = "paymentTMR_Tick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PG_2147808603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PG!MTB"
        threat_id = "2147808603"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "delete shadows /for=c: /all" wide //weight: 1
        $x_1_2 = "YOUR FILES HAVE BEEN ENCRYPTED" wide //weight: 1
        $x_1_3 = "/UnlockYourFiles" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PH_2147808634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PH!MTB"
        threat_id = "2147808634"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locky" wide //weight: 1
        $x_1_2 = "readme-locky.txt" wide //weight: 1
        $x_1_3 = "\\locky.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PK_2147808820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PK!MTB"
        threat_id = "2147808820"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe delete shadows /all / quiet" wide //weight: 1
        $x_1_2 = "All of your files have been encrypted" wide //weight: 1
        $x_1_3 = "HELP_DECRYPT_FILES.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PL_2147809414_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PL!MTB"
        threat_id = "2147809414"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".locked" wide //weight: 1
        $x_1_2 = "\\READ_IT.txt" wide //weight: 1
        $x_1_3 = "Yor File Locked" wide //weight: 1
        $x_1_4 = "\\password.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PM_2147815356_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PM!MTB"
        threat_id = "2147815356"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Goodwill Encryptor" ascii //weight: 1
        $x_1_2 = ".gdwill" wide //weight: 1
        $x_1_3 = "\\unlock your files.lnk" wide //weight: 1
        $x_1_4 = "\\Goodwill Encryptor.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_MKV_2147853210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.MKV!MTB"
        threat_id = "2147853210"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".Lockify" wide //weight: 1
        $x_1_2 = "Readme.HTA" wide //weight: 1
        $x_1_3 = "r.hta" wide //weight: 1
        $x_1_4 = "bytesToBeEncrypted" ascii //weight: 1
        $x_1_5 = "passwordBytes" ascii //weight: 1
        $x_1_6 = "CreatePassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_MKZ_2147853223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.MKZ!MTB"
        threat_id = "2147853223"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 95 00 00 0a 0d 7e 74 00 00 04 38 ?? ?? ?? 00 20 00 01 00 00 38 dd 00 00 00 16 3a c3 00 00 00 7e 76 00 00 04 38 d7 00 00 00 20 80 00 00 00 38 d3 00 00 00 1b 2c cf 02 07 20 e8 03 00 00 73 96 00 00 0a 13 04 7e 7a 00 00 04 09 7e 78 00 00 04 11 04 7e 33 00 00 04 09 28 3d 00 00 06 1e 5b 28 a6 00 00 06 28 a9 00 00 06 7e 7c 00 00 04 09 7e 78 00 00 04 11 04 7e 35 00 00 04 09 28 3d 00 00 06 1e 5b 28 a6 00 00 06 28 a9 00 00 06 7e 7e 00 00 04 09 17 28 ac 00 00 06 08 7e 80 00 00 04 09 28 af 00 00 06 17 73 97 00 00 0a 13 05 7e 82 00 00 04 11 05 04 16 04 8e 69 28 b2 00 00 06 7e 2e 00 00 04 11 05 28 37 00 00 06 16 2d e0 de 14}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_RDA_2147889175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.RDA!MTB"
        threat_id = "2147889175"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 06 7e 01 00 00 04 09 7e 01 00 00 04 6f 3b 00 00 0a 5e 6f 3c 00 00 0a 6f 43 00 00 0a 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_RDB_2147904597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.RDB!MTB"
        threat_id = "2147904597"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5d 6f 1e 00 00 0a 61 d2 9c 08 17 58 0c 08 06 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_SWA_2147927263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.SWA!MTB"
        threat_id = "2147927263"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "mrmalransom\\obj\\Release\\mrmalransom.pdb" ascii //weight: 2
        $x_2_2 = "Mr. Malware" ascii //weight: 2
        $x_2_3 = "$730c260a-a65b-4819-876c-6758ab836071" ascii //weight: 2
        $x_2_4 = "mrmalransom.Properties.Resources" ascii //weight: 2
        $x_1_5 = "Your computer files have been encrypted!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_HiddenTear_BA_2147937749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.BA!MTB"
        threat_id = "2147937749"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Ransomeware.pdb" ascii //weight: 1
        $x_1_2 = "Decrypt Your System" ascii //weight: 1
        $x_1_3 = "EncryptionKey" ascii //weight: 1
        $x_1_4 = "pay your payment faster before your system crashed" ascii //weight: 1
        $x_1_5 = "The File Have Been Decrypted" ascii //weight: 1
        $x_1_6 = "crypto and instructions on how to decrypt the system" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_PDZ_2147941719_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.PDZ!MTB"
        threat_id = "2147941719"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Your files have been encrypted" ascii //weight: 3
        $x_3_2 = "Any attempts to decrypt a file without permission will result in its deletion" ascii //weight: 3
        $x_2_3 = "ransom payment" ascii //weight: 2
        $x_2_4 = "FileKrypter Encrypted FIle|*.filekrypter|All Files|*.*" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_HiddenTear_AHT_2147946601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/HiddenTear.AHT!MTB"
        threat_id = "2147946601"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "HiddenTear"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 08 00 11 08 13 09 16 13 0a ?? ?? ?? ?? ?? 11 09 11 0a 9a 13 0b 00 11 0b 6f ?? 00 00 0a 2c 0f 11 0b 6f ?? 00 00 0a 19 fe 01 16 fe 01 2b 01 17 13 0e 11 0e 2c 05}  //weight: 2, accuracy: Low
        $x_1_2 = "The Security of This Computer Has Been Compromised" ascii //weight: 1
        $x_3_3 = "JupiterLocker has encrypted all the data on this computer with military-grade AES-256 encryption" ascii //weight: 3
        $x_1_4 = "We take our work seriously and understand that your data may be sensitive or important" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

