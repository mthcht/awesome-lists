rule Ransom_MSIL_FileCoder_E_2147725845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.E!bit"
        threat_id = "2147725845"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "HERE ARE LISTED YOUR ENCRYPTED FILES" wide //weight: 1
        $x_1_3 = "PAY NOW TO DECRYPT THE FILES" wide //weight: 1
        $x_1_4 = "I PAID, PLEASE DECRYPT MY FILES" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Ransom_MSIL_FileCoder_PA_2147744152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.PA!MTB"
        threat_id = "2147744152"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptedExtension" ascii //weight: 1
        $x_1_2 = "DecryptNoteFilename" ascii //weight: 1
        $x_1_3 = "ID_DP_FILE" ascii //weight: 1
        $x_1_4 = "LockerForValidKey" ascii //weight: 1
        $x_1_5 = "DeleteShadowCopies" ascii //weight: 1
        $x_1_6 = "CycleDefender" ascii //weight: 1
        $x_1_7 = "EncryptFolder" ascii //weight: 1
        $x_1_8 = "decodor@airmail.cc" wide //weight: 1
        $x_1_9 = ".kiss" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_PA_2147744152_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.PA!MTB"
        threat_id = "2147744152"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Encrypting files" wide //weight: 1
        $x_1_2 = "You have been struck with DUMB" wide //weight: 1
        $x_1_3 = "Your files have been encrypted" wide //weight: 1
        $x_1_4 = "leet haker" wide //weight: 1
        $x_1_5 = {5c 44 55 4d 42 [0-16] 5c 44 55 4d 42 5c 6f 62 6a 5c [0-21] 5c 44 55 4d 42 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_FileCoder_PB_2147745139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.PB!MTB"
        threat_id = "2147745139"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gov-ransomware" wide //weight: 1
        $x_1_2 = "Your computer has been locked and your files are now encrypted." ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "Send your Bitcoins here" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_PB_2147745139_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.PB!MTB"
        threat_id = "2147745139"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Y21kLmV4ZQ==" wide //weight: 1
        $x_1_2 = "L0Mgc3RhcnQgL01BWCA=" wide //weight: 1
        $x_1_3 = "extensionsToEncrypt" ascii //weight: 1
        $x_5_4 = "==QY0hmLT9VSfh0XU91XE9VQfV0XyAjMxI1L" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_BB_2147752685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.BB!MSR"
        threat_id = "2147752685"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "BB ransomware" ascii //weight: 2
        $x_2_2 = ".encryptedbyBB" ascii //weight: 2
        $x_2_3 = "Hello! I'm a BB, and Im encrypt your" ascii //weight: 2
        $x_1_4 = "Please give me a BTC To address:" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_IL_2147752688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.IL!MSR"
        threat_id = "2147752688"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EncryptedFiles" ascii //weight: 2
        $x_2_2 = "FirstRansomStartup" ascii //weight: 2
        $x_2_3 = ".likud" ascii //weight: 2
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run\\ILElection" ascii //weight: 1
        $x_2_5 = "ILElection2020_Ransomware" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_MK_2147756511_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MK!MSR"
        threat_id = "2147756511"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Oops, your personal files have been encrypted!" ascii //weight: 2
        $x_2_2 = "description.Text" ascii //weight: 2
        $x_2_3 = "vssadmin delete shadows /all /quiet" ascii //weight: 2
        $x_2_4 = "modify, rename, delete or change the encrypted (.dsec) files" ascii //weight: 2
        $x_1_5 = "Your photos, music, documents, work files, etc. are now encoded and unreadable." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCoder_AB_2147766650_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AB!MTB"
        threat_id = "2147766650"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_CryLocker_.exe" ascii //weight: 1
        $x_1_2 = "View_encrypt_file_list" ascii //weight: 1
        $x_1_3 = "get_BlueScreenFake" ascii //weight: 1
        $x_1_4 = "Policies\\System\\DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AB_2147766650_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AB!MTB"
        threat_id = "2147766650"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HEY. AS YOU ALREADY UNDERSTOOD, I HAVE ALL THE LOGINS/PASSWORDS" ascii //weight: 1
        $x_1_2 = "FOR ALL YOUR ACCOUNTS AND ENCRYPT SOME YOUR FILES." ascii //weight: 1
        $x_1_3 = "IF YOU CHOOSE 1ST WAY - SEND 0,0026 BTC (30$) TO WALLET" ascii //weight: 1
        $x_1_4 = "I DELETE YOU FROM MY DATABASE AND UNLCOK YOUR FILES" ascii //weight: 1
        $x_1_5 = "I SELL YOUR DATA AND EVERYTHING I FOUND ON THE BLACK MARKET" ascii //weight: 1
        $x_1_6 = "if you don't know how to buy bitcoin, just ask google" ascii //weight: 1
        $x_1_7 = "\\Release\\Install.pdb" ascii //weight: 1
        $x_1_8 = "\\Documents\\pay.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AC_2147797580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AC!MTB"
        threat_id = "2147797580"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Arcane Ransomware [ Your files are encrypted!]" ascii //weight: 1
        $x_1_2 = "YOUR FILES ARE FUCKING encrypted" ascii //weight: 1
        $x_1_3 = "decrypt my shit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_SM_2147807282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.SM!MTB"
        threat_id = "2147807282"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 04 07 09 91 58 06 09 06 8e 69 5d 91 58 20 00 01 00 00 5d 13 04 07 09 11 04 28 0b 00 00 06 00 00 09 17 58 0d 09 20 00 01 00 00 fe 04 13 08 11 08 2d cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AF_2147807870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AF!MTB"
        threat_id = "2147807870"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 0e 16 13 0f 2b 17 11 0e 11 0f 9a 13 10 00 11 10 28 07 00 00 06 00 00 11 0f 17 58 13 0f 11 0f 11 0e 8e 69 32 e1}  //weight: 2, accuracy: High
        $x_1_2 = "Maze\\obj\\Debug\\Maze.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AF_2147807870_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AF!MTB"
        threat_id = "2147807870"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RansomwareViper" wide //weight: 1
        $x_1_2 = "Viper_README" wide //weight: 1
        $x_1_3 = "Your files were encrypted by Viper Ransomware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AG_2147808867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AG!MTB"
        threat_id = "2147808867"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "@__RECOVER_YOUR_FILES__@.txt" wide //weight: 1
        $x_1_2 = "All of your documents,musics,videos have been encrypted" ascii //weight: 1
        $x_1_3 = "Time Time Ransomware" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_SG_2147840541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.SG!MTB"
        threat_id = "2147840541"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "NitroRansomware.Resources.wl.png" ascii //weight: 2
        $x_2_2 = "$d5e87439-21e6-4567-a877-6ad9bee00dc9" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_PBB_2147842599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.PBB!MTB"
        threat_id = "2147842599"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 18 5b 8d ?? ?? ?? ?? 0b 16 0c 2b 18 07 08 18 5b 02 08 18 6f ?? ?? ?? ?? 1f 10 28 ?? ?? ?? ?? 9c 08 18 58 0c 08 06 32 e4}  //weight: 1, accuracy: Low
        $x_1_2 = "SeroXen\\SeroXen\\obj\\x64\\Release\\SeroXen.pdb" ascii //weight: 1
        $x_1_3 = "Ace.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_CF_2147851031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.CF!MTB"
        threat_id = "2147851031"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encryption Attack Ransomware" wide //weight: 1
        $x_1_2 = "Give my files back!" wide //weight: 1
        $x_1_3 = "Error Get DecryptFile! Please Ask For Creator" wide //weight: 1
        $x_1_4 = "randomiv.bin" wide //weight: 1
        $x_1_5 = "EncryptFile" ascii //weight: 1
        $x_1_6 = "SSEAR.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AZ_2147896925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AZ!MTB"
        threat_id = "2147896925"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AceRansomware" ascii //weight: 1
        $x_1_2 = "encryptedFiles" ascii //weight: 1
        $x_1_3 = "DisableTskMGR" ascii //weight: 1
        $x_1_4 = "extensionsToEncrypt" ascii //weight: 1
        $x_1_5 = "DropDecrypter" ascii //weight: 1
        $x_1_6 = "AceDotNet.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_MVT_2147900672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVT!MTB"
        threat_id = "2147900672"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xaqipaxowq.exe" ascii //weight: 2
        $x_1_2 = "Zadilok" ascii //weight: 1
        $x_1_3 = "Biclavek" ascii //weight: 1
        $x_1_4 = "Copyright Edarimenum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCoder_MVT_2147900672_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVT!MTB"
        threat_id = "2147900672"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Fenrikware" ascii //weight: 2
        $x_1_2 = "files have been encrypted" ascii //weight: 1
        $x_1_3 = "ShadowCopy" ascii //weight: 1
        $x_1_4 = "FilumEncrypto" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCoder_MVB_2147902586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVB!MTB"
        threat_id = "2147902586"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "TinyTrigger.exe" ascii //weight: 5
        $x_2_2 = "Files are Encrypted by Tiny Trigger!" ascii //weight: 2
        $x_1_3 = "Live or Die" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
        $x_1_6 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCoder_MVC_2147902587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVC!MTB"
        threat_id = "2147902587"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TaeMinVirus.exe" ascii //weight: 2
        $x_1_2 = "I got into your computer" ascii //weight: 1
        $x_1_3 = "There's no exit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCoder_MVE_2147902589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVE!MTB"
        threat_id = "2147902589"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "AlcDif.exe" ascii //weight: 3
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_4 = "All your files are encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCoder_MVF_2147902591_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVF!MTB"
        threat_id = "2147902591"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Encrypter" ascii //weight: 1
        $x_1_2 = "Send Email To both Address" ascii //weight: 1
        $x_1_3 = "to kill the ransomware" ascii //weight: 1
        $x_1_4 = "BEFORE DECRYPTING TEST FILE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_MVH_2147903178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVH!MTB"
        threat_id = "2147903178"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "PS99Auto-Diamond" ascii //weight: 2
        $x_1_2 = "P.l.e.w.t.b.q.f._" ascii //weight: 1
        $x_2_3 = "set_UseShellExecute" ascii //weight: 2
        $x_1_4 = "GetExtension" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCoder_MVJ_2147903362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVJ!MTB"
        threat_id = "2147903362"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 78 04 00 70 73 b0 00 00 0a 0b 07 17 6f b1 00 00 0a 00 07 72 88 04 00 70 6f b2 00 00 0a 00 07 72 c2 04 00 70 6f b2 00 00 0a 00 07 28 b3 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_MVI_2147903727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVI!MTB"
        threat_id = "2147903727"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PedoCrypter" ascii //weight: 1
        $x_1_2 = "fileExtensions" ascii //weight: 1
        $x_1_3 = "!!!YOUR FILE HAS BEEN ENCRYPTED!!!.txt" ascii //weight: 1
        $x_1_4 = "A1c0rDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_MVK_2147905769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MVK!MTB"
        threat_id = "2147905769"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FileEncry.pdb" ascii //weight: 1
        $x_1_2 = "vssadmin delete shadows" wide //weight: 1
        $x_1_3 = "BouncyCastle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RHA_2147906031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHA!MTB"
        threat_id = "2147906031"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ProcessStartInfo" ascii //weight: 1
        $x_1_2 = "Clipboard" ascii //weight: 1
        $x_1_3 = "GetDrives" ascii //weight: 1
        $x_1_4 = "get_UserName" ascii //weight: 1
        $x_1_5 = "payload.exe" ascii //weight: 1
        $x_1_6 = "Callvirt" ascii //weight: 1
        $x_1_7 = "AsymmetricAlgorithm" ascii //weight: 1
        $x_1_8 = "get_CurrentDomain" ascii //weight: 1
        $x_1_9 = {4f 00 72 00 69 00 67 00 69 00 6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 ?? ?? 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_2_10 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 05 00 00 aa 01 00 00 00 00 00 ?? ?? 05 00 00 20}  //weight: 2, accuracy: Low
        $x_2_11 = {8c 1a 00 00 01 00 80 80 00 00 01 00 20 00 28 08 01 00 02 00 40 40 00 00 01 00 20 00 28 42 00 00 03 00 30 30 00 00 01 00 20 00 a8 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_YAR_2147906197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.YAR!MTB"
        threat_id = "2147906197"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 06 11 07 ?? ?? ?? ?? ?? 08 11 08 02 11 08 91 07 07 11 06 91 07 11 07 91 58 20 00 01 00 00 5d 91 61 d2 9c 11 08 17 58 13 08 11 08 02 8e 69 32 b3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_MV_2147907305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MV!MTB"
        threat_id = "2147907305"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows /all" ascii //weight: 1
        $x_1_2 = "EncDll.pdb" ascii //weight: 1
        $x_1_3 = "btc to my address" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_SGC_2147910059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.SGC!MTB"
        threat_id = "2147910059"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_WanaDecryptor" ascii //weight: 1
        $x_1_2 = ".WNCRY" wide //weight: 1
        $x_1_3 = "\\wallpaper\\WanaDecryptor.bmp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RHG_2147912432_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHG!MTB"
        threat_id = "2147912432"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SevenRecode" wide //weight: 1
        $x_1_2 = ".msh1xml" wide //weight: 1
        $x_1_3 = ".shtml" wide //weight: 1
        $x_1_4 = "C:\\Users\\Public\\Documents\\" wide //weight: 1
        $x_1_5 = "DisableRegistryTools" wide //weight: 1
        $x_1_6 = "DisableTaskMgr" wide //weight: 1
        $x_1_7 = "AndyMilo.jpg" wide //weight: 1
        $x_1_8 = "Wallpaper" wide //weight: 1
        $x_1_9 = "HideFiles" ascii //weight: 1
        $x_1_10 = "EncryptBytes" ascii //weight: 1
        $x_2_11 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RHK_2147912649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHK!MTB"
        threat_id = "2147912649"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DisableShutdown" wide //weight: 1
        $x_1_2 = "DisableChangePassword" wide //weight: 1
        $x_1_3 = "our files have been locked via an military encryptor" wide //weight: 1
        $x_1_4 = "Executable copied to startup" wide //weight: 1
        $x_1_5 = "DisableTaskMgr" wide //weight: 1
        $x_1_6 = "n.i.g.h.t.s.k.y.i.s.h.e.r.e.n.s" wide //weight: 1
        $x_1_7 = "Encrypting" wide //weight: 1
        $x_1_8 = "Bitcoin" wide //weight: 1
        $x_2_9 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RHC_2147913362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHC!MTB"
        threat_id = "2147913362"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ReadMe_LighterRansomware.txt" wide //weight: 1
        $x_1_2 = ".L0cked" wide //weight: 1
        $x_1_3 = "\\Contacts\\" wide //weight: 1
        $x_1_4 = "shutdown" wide //weight: 1
        $x_2_5 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 50 00 00 fa 27 00 00 14 00 00 00 00 00 00 ?? ?? 28 00 00 20 00 00 00 20 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_SGD_2147913815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.SGD!MTB"
        threat_id = "2147913815"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$10f1f037-fed9-4da2-8c6b-75bdd324b8f9" ascii //weight: 1
        $x_1_2 = "\\cryptobrick.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RDB_2147913879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RDB!MTB"
        threat_id = "2147913879"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GhostHacker" ascii //weight: 1
        $x_1_2 = "NoCry" ascii //weight: 1
        $x_1_3 = "50c49de9-914a-42e8-a9f6-285f7ca8c71e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RHD_2147914322_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHD!MTB"
        threat_id = "2147914322"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GetDelegateForFunctionPointer" wide //weight: 1
        $x_1_2 = "file:" wide //weight: 1
        $x_1_3 = "Location" wide //weight: 1
        $x_1_4 = "ResourceA" wide //weight: 1
        $x_1_5 = "Write" wide //weight: 1
        $x_1_6 = "Process" wide //weight: 1
        $x_1_7 = "Memory" wide //weight: 1
        $x_1_8 = "Close" wide //weight: 1
        $x_1_9 = "Handle" wide //weight: 1
        $x_1_10 = "kernel" wide //weight: 1
        $x_1_11 = "32.dll" wide //weight: 1
        $x_1_12 = "CreateDecryptor" ascii //weight: 1
        $x_2_13 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 50 00 00}  //weight: 2, accuracy: Low
        $x_2_14 = {66 89 81 34 a2 84 e6 cd 82 95 11 fa 8d 41 d5 c2}  //weight: 2, accuracy: High
        $x_10_15 = "Infected.exe" ascii //weight: 10
        $x_10_16 = "Client.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 12 of ($x_1_*))) or
            ((2 of ($x_10_*) and 6 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_FileCoder_RHQ_2147915576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHQ!MTB"
        threat_id = "2147915576"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "All of your files are encrypted and stolen" wide //weight: 1
        $x_1_2 = "Decryption is not possible without private key" wide //weight: 1
        $x_1_3 = "you have to pay 700 USD via Bitcoin at this adress" wide //weight: 1
        $x_1_4 = "contact us via Telegram t.me" wide //weight: 1
        $x_1_5 = "VirtualBoxVM" wide //weight: 1
        $x_1_6 = ".crypted" wide //weight: 1
        $x_1_7 = ".ibank" wide //weight: 1
        $x_1_8 = "LOOK_FOR_EXTENSIONS" ascii //weight: 1
        $x_1_9 = "IP tracker" ascii //weight: 1
        $x_1_10 = "ENCRYPT_EXTENSIONS" ascii //weight: 1
        $x_2_11 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0b 00 00 5e 00 00 00 08 00 00 00 00 00 00 6e 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RHR_2147916491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHR!MTB"
        threat_id = "2147916491"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "All your files are encrypted" wide //weight: 1
        $x_1_2 = "Do you want to decrypt your files" wide //weight: 1
        $x_1_3 = "Our Telegram:" wide //weight: 1
        $x_1_4 = "t.me/Poliex" wide //weight: 1
        $x_1_5 = "OneDrive" wide //weight: 1
        $x_1_6 = "backupdb" wide //weight: 1
        $x_1_7 = "bank" wide //weight: 1
        $x_1_8 = "README.txt" wide //weight: 1
        $x_1_9 = "EncryptFiles" ascii //weight: 1
        $x_1_10 = "pdf.exe" ascii //weight: 1
        $x_2_11 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 00 00 40 00 00 00 10 01 00 00 00 00 00 9e 5f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYA_2147919076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYA!MTB"
        threat_id = "2147919076"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Users\\Public\\Windows\\Ui\\unlock your files.lnk" wide //weight: 2
        $x_1_2 = "DeleteShadowCopies" ascii //weight: 1
        $x_1_3 = "alertmsg.zip" wide //weight: 1
        $x_1_4 = "error ha bhaiya" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYB_2147920016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYB!MTB"
        threat_id = "2147920016"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your files are encrypted using AES, ur ID:" wide //weight: 2
        $x_1_2 = "$1224ec38-e6b6-4980-a505-c0553cd21f21" ascii //weight: 1
        $x_1_3 = "AntiVMGPU" ascii //weight: 1
        $x_1_4 = "Morgan\\obj\\Release\\Morgan.pdb" ascii //weight: 1
        $x_1_5 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYC_2147920018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYC!MTB"
        threat_id = "2147920018"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Somnia.exe" wide //weight: 2
        $x_2_2 = "$1cffa9e8-71bd-4ad1-b514-d02bed459f2b" ascii //weight: 2
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "Users\\Admin\\source\\repos\\Somnia" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYC_2147920018_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYC!MTB"
        threat_id = "2147920018"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "HACKED BY PAPAZ" wide //weight: 2
        $x_1_2 = "papaz22@proton.me" wide //weight: 1
        $x_1_3 = "Benioku.txt" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYD_2147921624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYD!MTB"
        threat_id = "2147921624"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RanSomWare.exe" ascii //weight: 2
        $x_2_2 = "RanSomWare.Properties" ascii //weight: 2
        $x_1_3 = "$533e66fc-8b5c-4d67-8cbc-1cac8521de3b" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_MX_2147921690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MX!MTB"
        threat_id = "2147921690"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Flandreware" ascii //weight: 1
        $x_1_2 = "encrypted your precious data" ascii //weight: 1
        $x_1_3 = "Your system have been encrypted by Flandre" wide //weight: 1
        $x_1_4 = ".Scarlet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_MX_2147921690_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.MX!MTB"
        threat_id = "2147921690"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin delete shadows" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_3 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_4 = "wbadmin delete catalog -quiet" wide //weight: 1
        $x_1_5 = "your files are encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_FileCoder_AYF_2147922976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYF!MTB"
        threat_id = "2147922976"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Winlocker.Properties.Resources" wide //weight: 2
        $x_1_2 = "$8a3531d2-cb95-495c-ac17-327b37c5d0af" ascii //weight: 1
        $x_1_3 = "DisableTaskMgr" wide //weight: 1
        $x_1_4 = "DisableRegistryTools" wide //weight: 1
        $x_1_5 = "Windows\\kvoop.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYG_2147922977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYG!MTB"
        threat_id = "2147922977"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "xmb.pythonanywhere.com" ascii //weight: 2
        $x_1_2 = "You became victim of the razrusheniye ransomware!" ascii //weight: 1
        $x_1_3 = "If you report us AFTER restoration, we WILL attack you again!!!" ascii //weight: 1
        $x_1_4 = "%s.raz" ascii //weight: 1
        $x_1_5 = "AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RHAC_2147923578_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHAC!MTB"
        threat_id = "2147923578"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "Contact Me On Telegram: @doglovers3" wide //weight: 3
        $x_1_2 = "You Just Have 24 Hours To Unlock Your Computer" wide //weight: 1
        $x_1_3 = "All Files Will Be Deleted And Can't Be Recovered" wide //weight: 1
        $x_1_4 = ".docx" wide //weight: 1
        $x_2_5 = "Send Me 100 USDT To Unlock Your Computer" wide //weight: 2
        $x_2_6 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 30 00 00 20 0c 00 00 08 00 00 00 00 00 00 7e 3f 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYI_2147925314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYI!MTB"
        threat_id = "2147925314"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$3105a7da-42f3-45a4-8ba6-dc18159a7627" ascii //weight: 2
        $x_1_2 = "EncryptionInfo.txt" wide //weight: 1
        $x_1_3 = "All {0} files have been encrypted." wide //weight: 1
        $x_1_4 = "To decrypt your files, please contact us." wide //weight: 1
        $x_1_5 = "EncryptAllFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYJ_2147925543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYJ!MTB"
        threat_id = "2147925543"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GhostCry" wide //weight: 2
        $x_1_2 = "$c4368743-2543-479a-8a21-4feaa061dfc2" ascii //weight: 1
        $x_1_3 = "Encryption complete" wide //weight: 1
        $x_1_4 = "CreateMutexAndWriteToRegistry" ascii //weight: 1
        $x_1_5 = "EncryptFiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYK_2147925544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYK!MTB"
        threat_id = "2147925544"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cryptobrick.exe" ascii //weight: 2
        $x_1_2 = "$10f1f037-fed9-4da2-8c6b-75bdd324b8f9" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYL_2147925545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYL!MTB"
        threat_id = "2147925545"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$96606ae9-eb48-463b-b406-41d17d670ce7" ascii //weight: 2
        $x_1_2 = "You have only 45 seconds to read the rules and copy encrypted code in hex." wide //weight: 1
        $x_1_3 = "Jigsaw.Properties.Resources" wide //weight: 1
        $x_1_4 = "obj\\Debug\\Jigsaw.pdb" ascii //weight: 1
        $x_1_5 = "DisableTaskMgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYM_2147925549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYM!MTB"
        threat_id = "2147925549"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TARRGET MACHINE GOT INFECTED HERES THIER PRIVATE ID:" wide //weight: 2
        $x_1_2 = "And you will recive the decryptor for this ransomware." wide //weight: 1
        $x_1_3 = "DisableRegistryTools" wide //weight: 1
        $x_1_4 = "ransom.hacker.contact" wide //weight: 1
        $x_1_5 = "EncryptFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYN_2147925550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYN!MTB"
        threat_id = "2147925550"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Your system has been hacked with the AzzaSec ransomware virus" ascii //weight: 2
        $x_1_2 = "ransomeware\\obj\\Debug\\AzzaSec.pdb" ascii //weight: 1
        $x_1_3 = "Ooops, Your Files Have Been Encrypted" ascii //weight: 1
        $x_1_4 = "AzzaSec_Encryptor" wide //weight: 1
        $x_1_5 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RHAA_2147925678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHAA!MTB"
        threat_id = "2147925678"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "NoCry.exe" ascii //weight: 2
        $x_1_2 = "your important files are encrypted." ascii //weight: 1
        $x_1_3 = "Ooooops All Your Files Are Encrypted ,NoCry" ascii //weight: 1
        $x_1_4 = "Contact Me At Email To Get A Key" ascii //weight: 1
        $x_2_5 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 08 00 00 5a 05 00 00 06 00 00 00 00 00 00 2e 78 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_RHAH_2147929559_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.RHAH!MTB"
        threat_id = "2147929559"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {50 45 00 00 4c 01 03 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0b 01 0b 00 00 56 00 00 00 08 00 00 00 00 00 00 3e 75}  //weight: 2, accuracy: Low
        $x_3_2 = "All your files are stolen and encrypted" wide //weight: 3
        $x_1_3 = "RdpLocker" wide //weight: 1
        $x_1_4 = "you must pay for the decryption key" wide //weight: 1
        $x_1_5 = "wallet" wide //weight: 1
        $x_1_6 = "VirtualBoxVM" wide //weight: 1
        $x_1_7 = "backup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYQ_2147935291_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYQ!MTB"
        threat_id = "2147935291"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GX40 Ransomeware" wide //weight: 2
        $x_1_2 = "$afdc5238-2c89-4950-8491-7eafbc27a33a" ascii //weight: 1
        $x_1_3 = "All of your important files has been encrypted" wide //weight: 1
        $x_1_4 = "Ambarawa Cyber Army" wide //weight: 1
        $x_1_5 = "doEncrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYP_2147935292_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYP!MTB"
        threat_id = "2147935292"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Rans22.DecryptorApp" ascii //weight: 2
        $x_2_2 = "successfully encrypted!" wide //weight: 2
        $x_1_3 = "The program exits because a debugger was detected." wide //weight: 1
        $x_1_4 = "EncryptFile" ascii //weight: 1
        $x_1_5 = "SaveMachineIdToSaveDirectory" ascii //weight: 1
        $x_1_6 = "DecryptFilesInDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_SO_2147936300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.SO!MTB"
        threat_id = "2147936300"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Desktop\\YOU-BETTER-README.txt" ascii //weight: 2
        $x_2_2 = "Haha - All your files have been encrypted!!" ascii //weight: 2
        $x_2_3 = "NewEncryptApp.Properties.Resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_AYR_2147940212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.AYR!MTB"
        threat_id = "2147940212"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "freemovies.liveblog365.com" wide //weight: 2
        $x_1_2 = "Do you confirm your intention to utilize this string for decryption purposes?" wide //weight: 1
        $x_1_3 = "You are hit with a virus." wide //weight: 1
        $x_1_4 = "Your issue is that your computer is completely locked down. You need to pay up." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_FileCoder_SPX_2147942781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/FileCoder.SPX!MTB"
        threat_id = "2147942781"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 04 00 00 73 ?? 00 00 0a 0b 07 03 6f ?? 00 00 0a 6f ?? 00 00 0a 07 06 17 6f ?? 00 00 0a 0c 08 28 ?? 00 00 0a 0d 09 13 04 de 12 07 16 6f ?? 00 00 0a dc 07 2c 06 07 6f ?? 00 00 0a dc 11 04 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "vssadmin delete shadows /all /quiet & wmic shadowcopy delete" wide //weight: 1
        $x_1_3 = "bcdedit /set {default} bootstatuspolicy ignoreallfailures & bcdedit /set {default} recoveryenabled no" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

