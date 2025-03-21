rule Trojan_MSIL_FileCoder_RDA_2147838455_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.RDA!MTB"
        threat_id = "2147838455"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PayUpORCry" ascii //weight: 1
        $x_1_2 = "2bc81178-04e1-4a2e-b982-dbe7e3357801" ascii //weight: 1
        $x_1_3 = "user32" ascii //weight: 1
        $x_1_4 = "SystemParametersInfo" ascii //weight: 1
        $x_1_5 = "0400f03e-84be-4df9-b931-e9282ab2b5bc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARAQ_2147850735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARAQ!MTB"
        threat_id = "2147850735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\ransom_test\\obj\\Debug\\ransom_test.pdb" ascii //weight: 2
        $x_2_2 = "files arleady encrypted" ascii //weight: 2
        $x_2_3 = "DisableTaskMgr" ascii //weight: 2
        $x_2_4 = "Processhacker" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARAQ_2147850735_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARAQ!MTB"
        threat_id = "2147850735"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "\\Byte\\obj\\Debug\\Byte.pdb" ascii //weight: 4
        $x_2_2 = "Files encrypted: {0} | Payment: {1} | Status: {2}" ascii //weight: 2
        $x_2_3 = "Paid but waiting for 1 confirmation" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_NFJ_2147890300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.NFJ!MTB"
        threat_id = "2147890300"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 3a 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? ?? ?? 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 73 ?? 00 00 0a 0a 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? ?? ?? 06 73 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "SPIF_SWEDWINI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_NF_2147893379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.NF!MTB"
        threat_id = "2147893379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 17 28 ?? 00 00 06 02 02 04 28 ?? 00 00 06 16 28 ?? 00 00 06 28 ?? 00 00 06 16 28 ?? 00 00 06 0b}  //weight: 5, accuracy: Low
        $x_1_2 = "OnyxLocker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_NF_2147893379_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.NF!MTB"
        threat_id = "2147893379"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CalamityLocker.Resources.messagerogue.txt" ascii //weight: 2
        $x_1_2 = "Your system has been compromised by the RogueByte ransomware" ascii //weight: 1
        $x_1_3 = "In order to regain access to your system and files, you must send us 100$" ascii //weight: 1
        $x_1_4 = "Every 10 minutes a random encrypted file in your system will be deleted" ascii //weight: 1
        $x_1_5 = "If you fail to pay the ransom within 24 hours, your files will be lost" ascii //weight: 1
        $x_1_6 = "Monero can be bought from getmonero" ascii //weight: 1
        $x_1_7 = "By closing this window you will lose the possibility to decrypt your files" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_NC_2147893380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.NC!MTB"
        threat_id = "2147893380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 72 ?? 00 00 70 28 ?? 00 00 0a 0a 12 00 fe ?? ?? ?? ?? 01 6f ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 2b 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_NFF_2147896730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.NFF!MTB"
        threat_id = "2147896730"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 1a 00 00 0a 03 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 04 6f ?? 00 00 0a 0b 28 ?? 00 00 0a 07 6f ?? 00 00 0a 0b 02 06 07 28 ?? 00 00 06 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "PayOrDie.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_NFC_2147896731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.NFC!MTB"
        threat_id = "2147896731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 42 01 00 04 7e ?? ?? 00 04 28 ?? ?? 00 06 11 08 11 09 11 0b 11 09 59 28 ?? ?? 00 06 17 8d ?? ?? 00 01 28 ?? ?? 00 06 6f ?? ?? 00 0a 11 0b 17 58 13 09 11 0b 17}  //weight: 5, accuracy: Low
        $x_1_2 = "ML.NET Program" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARA_2147901362_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARA!MTB"
        threat_id = "2147901362"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ".FuckOff" ascii //weight: 2
        $x_2_2 = "\\UrFile.TXT" ascii //weight: 2
        $x_2_3 = "You have Been Hack3d" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARA_2147901362_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARA!MTB"
        threat_id = "2147901362"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = ":\\Users\\Worm\\source\\repos\\BSOD\\BSOD\\obj\\Debug\\BSOD.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARA_2147901362_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARA!MTB"
        threat_id = "2147901362"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 9a 0c 00 08 28 ?? ?? ?? 06 00 08 28 ?? ?? ?? 06 00 00 07 17 58 0b 07 06 8e 69 32 e2}  //weight: 2, accuracy: Low
        $x_2_2 = "\\LockBIT\\systemID" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARA_2147901362_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARA!MTB"
        threat_id = "2147901362"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 07 11 07 06 08 9a 28 ?? ?? ?? 0a 7d ?? ?? ?? 04 06 08 9a 28 ?? ?? ?? 0a 0d 7e ?? ?? ?? 04 11 07 fe ?? ?? ?? ?? 06 73 ?? ?? ?? 0a 28 ?? ?? ?? 2b 39 ?? ?? ?? ?? 09 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 39 ?? ?? ?? ?? 06 08 9a 73 ?? ?? ?? 0a 13 04 11 04 6f ?? ?? ?? 0a 20 50 c3 10 00 6a 2f 4b 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 19 5b 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 13 05 06 08 9a 11 05 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 06 08 9a 06 08 9a 72 ?? ?? ?? 70 1a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 2b 49 28 ?? ?? ?? 0a 11 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 19 5b 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 13 06 06 08 9a 11 06 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 06 08 9a 06 08 9a 72 ?? ?? ?? 70 1a 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 07 2c 17 16 0b 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARAZ_2147909212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARAZ!MTB"
        threat_id = "2147909212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Conti.pdb" ascii //weight: 2
        $x_2_2 = "__DECRYPT_NOTE__" ascii //weight: 2
        $x_2_3 = "CONTI_LOG.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARAZ_2147909212_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARAZ!MTB"
        threat_id = "2147909212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\BlackRansomwareFireeye.pdb" ascii //weight: 2
        $x_2_2 = "EvilBillingAddressForBitcoins" wide //weight: 2
        $x_2_3 = "\\victim\\Desktop" wide //weight: 2
        $x_2_4 = "Your files will be lost" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARAX_2147909496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARAX!MTB"
        threat_id = "2147909496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "clippy_ransomware.Properties.Resources" ascii //weight: 2
        $x_2_2 = "encrypted files" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_ARAX_2147909496_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARAX!MTB"
        threat_id = "2147909496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RansomwarePOC" ascii //weight: 2
        $x_2_2 = "encryptFolderContents" ascii //weight: 2
        $x_2_3 = "dropRansomLetter" ascii //weight: 2
        $x_2_4 = "txtBitcoinAddress" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_FileCoder_ARAX_2147909496_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.ARAX!MTB"
        threat_id = "2147909496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "EncryptFile" ascii //weight: 6
        $x_1_2 = "DisableControlPanel" ascii //weight: 1
        $x_1_3 = "DisablePowershell" ascii //weight: 1
        $x_1_4 = "DisableRun" wide //weight: 1
        $x_1_5 = "DisableTaskMgr" wide //weight: 1
        $x_1_6 = "DisableRegistryTools" wide //weight: 1
        $x_1_7 = "DisableCMD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_SL_2147909720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.SL!MTB"
        threat_id = "2147909720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KadavroVector" ascii //weight: 1
        $x_1_2 = "KadavroVectorRansomware.My.Resources" ascii //weight: 1
        $x_1_3 = "$50c49de9-914a-42e8-a9f6-285f7ca8c71e" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_MV_2147911671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.MV!MTB"
        threat_id = "2147911671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "fakecry.pdb" ascii //weight: 10
        $x_1_2 = "bitcoin" ascii //weight: 1
        $x_1_3 = "your files have been encrypted" wide //weight: 1
        $x_10_4 = "Ransomware.pdb" ascii //weight: 10
        $x_10_5 = "Calculator.exe" ascii //weight: 10
        $x_1_6 = "EncryptFile" ascii //weight: 1
        $x_1_7 = "payment confirmation" wide //weight: 1
        $x_10_8 = "projectmars.exe" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_FileCoder_MD_2147911672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.MD!MTB"
        threat_id = "2147911672"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "disableRecoveryMode" ascii //weight: 1
        $x_1_2 = "checkAdminPrivilage" ascii //weight: 1
        $x_1_3 = "deleteShadowCopies" ascii //weight: 1
        $x_1_4 = "encryptedFileExtension" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_MA_2147912700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.MA!MTB"
        threat_id = "2147912700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 11 00 00 70 28 3a 00 00 06 7e 1e 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_MH_2147913436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.MH!MTB"
        threat_id = "2147913436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Donnyhub" ascii //weight: 10
        $x_1_2 = "CreateEncryptor" ascii //weight: 1
        $x_1_3 = "DecryptionKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_MK_2147913699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.MK!MTB"
        threat_id = "2147913699"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "files on your computer" wide //weight: 1
        $x_1_2 = "personal decryption code" wide //weight: 1
        $x_1_3 = "keygroup777" wide //weight: 1
        $x_1_4 = "bitcoin" wide //weight: 1
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_MSIL_FileCoder_RP_2147914162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.RP!MTB"
        threat_id = "2147914162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 02 00 00 06 06 20 c3 01 00 00 58 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = {06 1f 42 58 0a 7e ?? ?? ?? ?? 06 1f 35 59 97 29 ?? ?? ?? ?? 7e ?? ?? ?? ?? 06 1f 34 59 97 29 ?? ?? ?? ?? 2c 02 17 2a 16 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_MJ_2147915203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.MJ!MTB"
        threat_id = "2147915203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 03 00 00 04 7e 02 00 00 04 07 28 07 00 00 06 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_B_2147916191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.B!MTB"
        threat_id = "2147916191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_PersonalID" ascii //weight: 1
        $x_1_2 = "GetSystemID" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "get_Task" ascii //weight: 1
        $x_1_5 = "get_disk" ascii //weight: 1
        $x_1_6 = "Encryption" ascii //weight: 1
        $x_1_7 = "set_PersistKey" ascii //weight: 1
        $x_1_8 = "Startup" ascii //weight: 1
        $x_1_9 = "get_Files" ascii //weight: 1
        $x_1_10 = "set_Files" ascii //weight: 1
        $x_1_11 = "RunEncrypt" ascii //weight: 1
        $x_1_12 = "AesEncrypt" ascii //weight: 1
        $x_1_13 = "HttpWebRequest" ascii //weight: 1
        $x_1_14 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 1
        $x_1_15 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_16 = "ReadAllText" ascii //weight: 1
        $x_1_17 = "WriteAllText" ascii //weight: 1
        $x_1_18 = "GetEntryAssembly" ascii //weight: 1
        $x_1_19 = "CreateDirectory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_SM_2147917678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.SM!MTB"
        threat_id = "2147917678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 94 0b 07 16 32 16 07 02 6f 3a 00 00 0a 2f 0d 06 02 07 6f 3b 00 00 0a 6f 3c 00 00 0a 09 17 58 0d 09 08 8e 69 32 d8}  //weight: 2, accuracy: High
        $x_2_2 = "All your files are stolen and encrypted" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_NK_2147920280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.NK!MTB"
        threat_id = "2147920280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 08 09 11 08 16 03 6f ?? 00 00 0a 26 07 08 11 08 28 ?? 00 00 06 13 09 09}  //weight: 4, accuracy: Low
        $x_1_2 = "windows.old.old" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_DF_2147923701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.DF!MTB"
        threat_id = "2147923701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {28 2e 00 00 0a 11 07 6f 2f 00 00 0a 13 08 73 13 00 00 06 13 09}  //weight: 4, accuracy: High
        $x_3_2 = "Votre Cle pour payment" wide //weight: 3
        $x_3_3 = "C:\\Users\\Yannis\\Desktop\\majordom\\client\\major\\majordom\\obj\\Debug\\major.pdb" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_PM_2147928682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.PM!MTB"
        threat_id = "2147928682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 dc 06 07 28 ?? 00 00 06 0c 02 08 28 ?? 00 00 0a 00 02 02 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 00 2a}  //weight: 2, accuracy: Low
        $x_2_2 = ".locked" wide //weight: 2
        $x_1_3 = "Files have been encrypted" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_PN_2147929189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.PN!MTB"
        threat_id = "2147929189"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 06 16 11 07 6f ?? 00 00 0a 08 11 06 16 20 ?? 20 00 00 6f ?? 00 00 0a 25 13 07 16 30 e0 11 04 6f ?? 00 00 0a 72 e4 05 00 70 02 72 56 07 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a de 0c}  //weight: 2, accuracy: Low
        $x_2_2 = "What do I have to do to break the encryption" wide //weight: 2
        $x_1_3 = "the encryption will be removed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_PMI_2147929192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.PMI!MTB"
        threat_id = "2147929192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "NoCry Ransomware" ascii //weight: 3
        $x_2_2 = "You have been hacked" wide //weight: 2
        $x_2_3 = "$50c49de9-914a-42e8-a9f6-285f7ca8c71e" ascii //weight: 2
        $x_1_4 = "your files have been destroyed" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_PMCD_2147929392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.PMCD!MTB"
        threat_id = "2147929392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 fe 01 0a 06 2c 45 00 28 ?? 00 00 06 80 2f 00 00 04 7e 27 00 00 04 28 ?? 00 00 0a 16 fe 01 0b 07 2c 12 00 7e 27 00 00 04 28 ?? 00 00 06 28 ?? 00 00 0a 00 00 1f 14 16 7e 27 00 00 04 19 28 ?? 00 00 06 26 17 28 ?? 00 00 06 00 00}  //weight: 3, accuracy: Low
        $x_2_2 = "GhostCry Ransomware" wide //weight: 2
        $x_1_3 = "Success_Decrypt" wide //weight: 1
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_FileCoder_PML_2147936649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/FileCoder.PML!MTB"
        threat_id = "2147936649"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "FileCoder"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0c 9a 6f ?? 00 00 0a 72 0e 07 00 70 28 ?? 00 00 0a 39 cc 00 00 00 11 06 11 0c 9a 6f ?? 00 00 0a 13 0d 11 0d 28 ?? 00 00 0a 26 11 06 11 0c 9a 6f ?? 00 00 0a 13 0e}  //weight: 3, accuracy: Low
        $x_2_2 = {72 24 07 00 70 28 ?? 00 00 0a 2c 47 11 0d 11 07 72 20 07 00 70 11 06 11 0c 9a 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 09 72 f8 06 00 70 28 3f 00 00 0a 11 0e 72 20 07 00 70 11 0f 72 0e 07 00 70 28 51 00 00 0a 28 52 00 00 0a 11 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

