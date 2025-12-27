rule TrojanSpy_MSIL_Stealer_2147753972_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer!MTB"
        threat_id = "2147753972"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 02 07 91 6f ?? ?? ?? 0a 00 00 07 25 17 59 0b 16 fe ?? 0c 08 2d e7}  //weight: 5, accuracy: Low
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "http://107.173.191.123/swift/Fepviueeh_Djesbqqi.jpg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_MA_2147811261_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.MA!MTB"
        threat_id = "2147811261"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BUY CRYP" wide //weight: 1
        $x_1_2 = "@PulsarCrypter_bot" wide //weight: 1
        $x_1_3 = "af34ff3a-87fb-4d8b-b564-48f27b20b26f" ascii //weight: 1
        $x_1_4 = "rkDhOFY" wide //weight: 1
        $x_1_5 = "GetDomain" ascii //weight: 1
        $x_1_6 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_7 = "GetThreadContext" wide //weight: 1
        $x_1_8 = "ReadProcessMemory" wide //weight: 1
        $x_1_9 = "WriteProcessMemory" wide //weight: 1
        $x_1_10 = "ResumeThread" wide //weight: 1
        $x_1_11 = "DynamicDllInvoke" wide //weight: 1
        $x_1_12 = "GetBytes" ascii //weight: 1
        $x_1_13 = "Kill" ascii //weight: 1
        $x_1_14 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_MC_2147811459_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.MC!MTB"
        threat_id = "2147811459"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JaYGVybyIpDQp9DQo=" wide //weight: 1
        $x_1_2 = "-whatt" wide //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "-extdummt" wide //weight: 1
        $x_1_5 = "-zzxtract" wide //weight: 1
        $x_1_6 = "-debug" wide //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "PromptForPassword" ascii //weight: 1
        $x_1_9 = "getPassword" ascii //weight: 1
        $x_1_10 = "Credential_Form" ascii //weight: 1
        $x_1_11 = "USERNAME_TARGET_CREDENTIALS" ascii //weight: 1
        $x_1_12 = "get_ControlKeyState" ascii //weight: 1
        $x_1_13 = "PowerShell" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_MD_2147811766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.MD!MTB"
        threat_id = "2147811766"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-whatt" wide //weight: 1
        $x_1_2 = "-extdummt" wide //weight: 1
        $x_1_3 = "-zzxtract" wide //weight: 1
        $x_1_4 = "-debug" wide //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "Iw0KIyBDT05GSUd" wide //weight: 1
        $x_1_7 = "PromptForPassword" ascii //weight: 1
        $x_1_8 = "Keyboard_Form_KeyDown" ascii //weight: 1
        $x_1_9 = "Credential_Form" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_MH_2147814213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.MH!MTB"
        threat_id = "2147814213"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DownloadData" ascii //weight: 1
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
        $x_1_4 = {6c 00 6c 00 64 00 2e 00 78 00 2f 00 [0-96] 2f 00 73 00 74 00 6e 00 65 00 6d 00 68 00 63 00 61 00 74 00 74 00 61 00 2f 00 6d 00 6f 00 63 00 2e 00 70 00 70 00 61 00 64 00 72 00 6f 00 63 00 73 00 69 00 64 00 2e 00 6e 00 64 00 63 00 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_5 = {65 00 78 00 65 00 2e 00 [0-112] 2f 00 73 00 74 00 6e 00 65 00 6d 00 68 00 63 00 61 00 74 00 74 00 61 00 2f 00 6d 00 6f 00 63 00 2e 00 70 00 70 00 61 00 64 00 72 00 6f 00 63 00 73 00 69 00 64 00 2e 00 6e 00 64 00 63 00 2f 00 2f 00 3a 00 73 00 70 00 74 00 74 00 68 00}  //weight: 1, accuracy: Low
        $x_1_6 = "Create__Instance" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "ts_Transaction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_MI_2147815333_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.MI!MTB"
        threat_id = "2147815333"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a fe 0e 01 00 fe 0c 01 00 73 ?? ?? ?? 0a fe 0e 02 00 14 fe 0e 03 00 14 fe 0e 04 00 28 ?? ?? ?? 0a fe 0c 02 00 fe 0c 00 00 28 ?? ?? ?? 0a 8e 69 20 10 00 00 00 59 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 04 00 fe 0c 01 00 20 f0 ff ff ff 6a 20 02 00 00 00 6f ?? ?? ?? 0a 26 fe 0c 02 00 20 10 00 00 00 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a fe 0e 03 00 fe 0c 04 00 fe 0c 03 00 28 ?? ?? ?? 0a fe 0e 05 00 fe 0c 05 00 39 06 00 00 00 73 26 00 00 0a 7a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "MutexAccessRule" ascii //weight: 1
        $x_1_3 = "FromBase64TransformMode" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "CreateInstance" ascii //weight: 1
        $x_1_6 = "TransformFinalBlock" ascii //weight: 1
        $x_1_7 = "RegistryKeyPermissionCheck" ascii //weight: 1
        $x_1_8 = "CryptoKeyAccessRule" ascii //weight: 1
        $x_1_9 = "CreateDecryptor" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_1_11 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_MK_2147816214_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.MK!MTB"
        threat_id = "2147816214"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 01 16 11 01 8e 69 28 1a 00 00 0a 13 ?? 38 ?? 00 00 00 [0-24] 11 ?? 16 11 ?? 8e 69 28 ?? ?? ?? ?? 13 04 38 ?? ff ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {02 8e 69 8d 09 00 00 01 13 ?? 38 12 00 00 00 fe 0c ?? 00 45 01 00 00 00 ?? 00 00 00 38 ?? 00 00 00 11 ?? 11 ?? 16 11 ?? 8e 69 [0-31] 26 20 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "FromBase64CharArray" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
        $x_1_8 = "base64EncodedData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_ML_2147817737_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.ML!MTB"
        threat_id = "2147817737"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/&& svchost.exe /stext logs.txt" wide //weight: 1
        $x_1_2 = "/cmdkodu.txt" wide //weight: 1
        $x_1_3 = "Software\\Policies\\Microsoft\\Windows Defender" wide //weight: 1
        $x_1_4 = "DisableAntiSpyware" wide //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "DisableAntiVirus" wide //weight: 1
        $x_1_8 = "shutdown.exe" wide //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "NetworkCredential" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_MN_2147819713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.MN!MTB"
        threat_id = "2147819713"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 26 08 28 ?? ?? ?? 0a 0d 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 13 04 72 ?? ?? ?? 70 72 ?? 01 00 70 72 ?? 01 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 28 ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 13 06 07 28 ?? ?? ?? 0a 13 07 28 ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a 13 08 73 ?? ?? ?? 0a 11 08 28 ?? ?? ?? 0a 13 09 1f 2c 8d ?? 00 00 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 13 0a 28 ?? ?? ?? 0a 11 0a 6f ?? ?? ?? 0a 13 0b 06 11 04 6f ?? ?? ?? 0a 13 0c 19 8d ?? 00 00 01 13 26 11 26 16}  //weight: 1, accuracy: Low
        $x_1_2 = "C:\\Windows\\regedit.exe" wide //weight: 1
        $x_1_3 = "GetRandomAlphaNumeric" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_RK_2147819843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.RK!MTB"
        threat_id = "2147819843"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Q2xpZW50JQ==" ascii //weight: 1
        $x_1_2 = "DownloadString" ascii //weight: 1
        $x_1_3 = "C:\\Users\\ringz\\Documents\\xRAT 2.0\\xRAT-master\\C\\obj\\Release\\Client.pdb" ascii //weight: 1
        $x_1_4 = "get_PotentiallyVulnerablePasswords" ascii //weight: 1
        $x_1_5 = "AddClipboardFormatListener" ascii //weight: 1
        $x_1_6 = "CreateToolhelp32Snapshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SL_2147914438_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SL!MTB"
        threat_id = "2147914438"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 72 a5 00 00 70 6f 19 00 00 0a 6f 1a 00 00 0a 0d 09 08 6f 1b 00 00 0a 08 6f 0c 00 00 0a 0a dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SM_2147914440_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SM!MTB"
        threat_id = "2147914440"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 59 00 00 0a 13 09 12 09 fe 16 28 00 00 01 6f 5a 00 00 0a 28 41 00 00 0a 28 2d 00 00 0a 16 13 08 de 03}  //weight: 2, accuracy: High
        $x_2_2 = "imageclass.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SO_2147914441_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SO!MTB"
        threat_id = "2147914441"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 3c 11 0e 11 3c 11 1f 59 61 13 0e 11 1f 11 0e 17 63 58 13 1f}  //weight: 2, accuracy: High
        $x_2_2 = "imageclass.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SN_2147914442_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SN!MTB"
        threat_id = "2147914442"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 38 00 00 04 06 07 03 6f 40 00 00 0a 0c 08 2c 0f 07 08 58 0b 03 08 59 fe 0b 01 00 03 16 30 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SP_2147917680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SP!MTB"
        threat_id = "2147917680"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 03 06 7e 04 00 00 04 06 91 04 06 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e 04 00 00 04 8e 69 fe 04 0b 07 2d d9}  //weight: 2, accuracy: High
        $x_2_2 = "Shroud.Properties.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SQ_2147918589_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SQ!MTB"
        threat_id = "2147918589"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Tic_Tac_Toe.TicTacToePreview.resources" ascii //weight: 2
        $x_2_2 = "$5302f5a7-7100-4f7a-a26b-7ba1af8623d8" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_PQ_2147919303_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.PQ!MTB"
        threat_id = "2147919303"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_7_1 = "resources/jkghhjf.jpg" wide //weight: 7
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SSF_2147925317_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SSF!MTB"
        threat_id = "2147925317"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 2c 00 00 0a 73 2d 00 00 0a 20 f4 01 00 00 28 ?? ?? ?? 06 25 26 28 2e 00 00 0a 25 26 6f 2f 00 00 0a 25 26 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SU_2147925574_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SU!MTB"
        threat_id = "2147925574"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 0a 00 00 04 11 09 11 0b 58 91 08 11 0b 91 2e 05 16 13 0a 2b 0d 11 0b 17 58 13 0b 11 0b 08 8e 69 32 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SU_2147925574_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SU!MTB"
        threat_id = "2147925574"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Ahazujadar" ascii //weight: 2
        $x_2_2 = "Oqowemecalalibabuhuha" ascii //weight: 2
        $x_2_3 = "Ubakacupikucorod" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_PTQ_2147928684_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.PTQ!MTB"
        threat_id = "2147928684"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FirefoxCookies.txt" wide //weight: 2
        $x_2_2 = "EdgePasswords.txt" wide //weight: 2
        $x_2_3 = "Electrum\\wallets" wide //weight: 2
        $x_2_4 = "Dogecoin\\wallet" wide //weight: 2
        $x_2_5 = "$a16abbb4-985b-4db2-a80c-21268b26c73d" ascii //weight: 2
        $x_2_6 = "Stealer.Edge" ascii //weight: 2
        $x_1_7 = "Telegram" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Stealer_SV_2147936259_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SV!MTB"
        threat_id = "2147936259"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$WRITE_URL" ascii //weight: 2
        $x_2_2 = "bihjfosihuwgighuzhdc.tawor33971.workers.dev" ascii //weight: 2
        $x_2_3 = "$screenshot_path = \"$env:USERPROFILE\\AppData\\Local\\Temp\\screenshot.png" ascii //weight: 2
        $x_1_4 = "ratnew.ps1" ascii //weight: 1
        $x_1_5 = "ghhhh.ps1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_MSIL_Stealer_SY_2147952265_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Stealer.SY!MTB"
        threat_id = "2147952265"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Stealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 69 02 00 70 28 5d 01 00 0a 26 02 28 12 00 00 0a 0a 28 33 00 00 0a 06 16 06 8e 69 6f cf 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

