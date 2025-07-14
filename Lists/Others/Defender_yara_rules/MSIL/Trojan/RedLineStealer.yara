rule Trojan_MSIL_RedLineStealer_ZZ_2147771875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ZZ!MTB"
        threat_id = "2147771875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DetectCreditCardType" ascii //weight: 1
        $x_1_2 = "ParseBrowsers" ascii //weight: 1
        $x_1_3 = "CredentialsStage" ascii //weight: 1
        $x_1_4 = "RedLine.Reburn.Models" ascii //weight: 1
        $x_1_5 = "get_GrabVPN" ascii //weight: 1
        $x_1_6 = "set_GrabVPN" ascii //weight: 1
        $x_1_7 = "get_NordVPN" ascii //weight: 1
        $x_1_8 = "set_NordVPN" ascii //weight: 1
        $x_1_9 = "get_OpenVPN" ascii //weight: 1
        $x_1_10 = "set_OpenVPN" ascii //weight: 1
        $x_1_11 = "get_ProtonVPN" ascii //weight: 1
        $x_1_12 = "set_ProtonVPN" ascii //weight: 1
        $x_1_13 = "get_SessionId" ascii //weight: 1
        $x_1_14 = "get_passwordField" ascii //weight: 1
        $x_1_15 = "set_passwordField" ascii //weight: 1
        $x_1_16 = "get_usernameField" ascii //weight: 1
        $x_1_17 = "set_usernameField" ascii //weight: 1
        $x_1_18 = "RedLine.Reburn.Data" ascii //weight: 1
        $x_1_19 = "get_WalletDir" ascii //weight: 1
        $x_1_20 = "set_WalletDir" ascii //weight: 1
        $x_1_21 = "get_CreditCards" ascii //weight: 1
        $x_1_22 = "set_CreditCards" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MK_2147784121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MK!MTB"
        threat_id = "2147784121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 03 8e 69 17 da 13 05 16 13 08 2b 1b [0-4] 11 04 11 08 08 11 08 08 8e 69 5d 91 03 11 08 91 61 b4 9c [0-4] 11 08 17 d6 13 08 11 08 11 05 fe 02 16 fe 01 13 09 11 09 2d d6 11 04 13 0a 2b 00 11 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "DangerousGetHandle" ascii //weight: 1
        $x_1_4 = "DebuggableAttribute" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "Replace" ascii //weight: 1
        $x_1_8 = "add_KeyDown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MK_2147784121_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MK!MTB"
        threat_id = "2147784121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BLOWJOB" ascii //weight: 1
        $x_1_2 = "CUMSHOT" ascii //weight: 1
        $x_1_3 = "BUY CRYP" ascii //weight: 1
        $x_1_4 = "@PulsarCrypter_bot" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_9 = "GetThreadContext" ascii //weight: 1
        $x_1_10 = "ReadProcessMemory" ascii //weight: 1
        $x_1_11 = "WriteProcessMemory" ascii //weight: 1
        $x_1_12 = "SetThreadContext" ascii //weight: 1
        $x_1_13 = "DynamicDllInvoke" ascii //weight: 1
        $x_1_14 = "DynamicDllModule" ascii //weight: 1
        $x_1_15 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MK_2147784121_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MK!MTB"
        threat_id = "2147784121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "76"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "*.wallet" ascii //weight: 10
        $x_10_2 = "Wallet@" ascii //weight: 10
        $x_2_3 = "-*.lo--g" ascii //weight: 2
        $x_10_4 = "com.liberty.jaxx" ascii //weight: 10
        $x_10_5 = "SELECT * FROM Win32_Processor" ascii //weight: 10
        $x_2_6 = "NumberOfCores" ascii //weight: 2
        $x_2_7 = "AdapterRAM" ascii //weight: 2
        $x_2_8 = "AntqueiresivirusProdqueiresuctN" ascii //weight: 2
        $x_10_9 = "SELECT * FROM Win32_VideoController" ascii //weight: 10
        $x_10_10 = "shell\\open\\command" ascii //weight: 10
        $x_10_11 = "SELECT * FROM Win32_DiskDrive" ascii //weight: 10
        $x_10_12 = "SELECT * FROM Win32_OperatingSystem" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_10_*) and 3 of ($x_2_*))) or
            ((8 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_RedLineStealer_MB_2147794773_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MB!MTB"
        threat_id = "2147794773"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 8d 09 00 00 01 13 08 38 ?? ?? ?? ?? fe ?? ?? ?? 45 ?? ?? ?? ?? ?? ?? ?? ?? 38 ?? ?? ?? ?? 11 08 13 [0-32] 11 07 11 08 16 11 08 8e 69 6f 3b 00 00 0a 26}  //weight: 1, accuracy: Low
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "base64EncodedData" ascii //weight: 1
        $x_1_5 = "FromBase64CharArray" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MB_2147794773_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MB!MTB"
        threat_id = "2147794773"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetType" ascii //weight: 1
        $x_1_2 = "GetString" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "DownloadFile" ascii //weight: 1
        $x_1_6 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_7 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_8 = "CreateDecryptor" ascii //weight: 1
        $x_10_9 = {d2 f0 a4 9d 82 47 f3 24 19 a6 76 bc 66 ef 7b e2 0a 77 4a cd be 50 ae c8 1c 20 37 2f b2 55 9f 7e ae 97 88 93 e0 a3 31 fa ae 97 88 93 e0 a3 31 fa ae 97 88 93 e0 a3 31 fa ec b5 20 83 24 75 01 67 f4 7e be 23 ad d6 44 53 79 ab 23 e4 b1 5e 02 78 09 e8 94 79 50 e2 49 a4 6e 80 ee 08 a7 51 ec 7f 2a 2d f8 85 d9 23 98 ba 38 b0 4f 51 60 e0 fa 28 c3 a2 53 23 28 4e 93 f3 61 7d 42 20 89 21 2a 77 de fc 23 91 e5 57 f7 ce 5c 1e 47 60 f1 88 5b 3b 16 aa de 0c 5f 38 a9 c1 ad 37 ad 09 4c b7 e8 35 ed 75 06 ed e7 e2 25 52 cf ce e3 0d b6 b4 5b b3 b8 12 91 60 2a 26 c7 e8 f5 0b 84 5d 8d 50 84 ae 3c ce a3 64}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_DC_2147795890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.DC!MTB"
        threat_id = "2147795890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 1, accuracy: High
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "/cdn.discordapp.com/attachments/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_DD_2147795891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.DD!MTB"
        threat_id = "2147795891"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HKGASHSAEY_GASHSACURREGASHSANT_USGASHSAER\\SoGASHSAftwGASHSAare\\BrowseGASHSArOfGASHSADea\\BrowseGASHSArOfDGASHSAea" ascii //weight: 1
        $x_1_2 = "ApRCApDRCAata\\RoaRCAming" ascii //weight: 1
        $x_1_3 = "opENCRYPTenENCRYPT" ascii //weight: 1
        $x_1_4 = "FAASD.FAASDexFAASDe" ascii //weight: 1
        $x_1_5 = "usDFSDAser_DFSDAsauthDFSDAs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_SD_2147796262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.SD!MTB"
        threat_id = "2147796262"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "OnlineLicensing.dll" ascii //weight: 3
        $x_3_2 = "WriteCachedClientRightsToken" ascii //weight: 3
        $x_3_3 = "7qOtexsrbaRqmBuT6CqBZg==" ascii //weight: 3
        $x_3_4 = "i9Su6ghOkJi7X57wjuNwgHkQOT8EoCvP138jYo/hb44=" ascii //weight: 3
        $x_3_5 = "telemetryLogger" ascii //weight: 3
        $x_3_6 = "OnlineLicensing.pdb" ascii //weight: 3
        $x_3_7 = "Nerdbank.GitVersioning.Tasks" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_DB_2147796544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.DB!MTB"
        threat_id = "2147796544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "//cdn.discordapp.com/attachments/" ascii //weight: 1
        $x_1_2 = "SteamCloudFileManagerLite.upload" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "WindowsFormsApp" ascii //weight: 1
        $x_1_6 = "Injection Host:" ascii //weight: 1
        $x_1_7 = "Nirmala UI" ascii //weight: 1
        $x_1_8 = "starter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MD_2147796700_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MD!MTB"
        threat_id = "2147796700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 0f 07 17 d6 20 00 01 00 00 5d 0b 08 11 05 07 94 d6 20 00 01 00 00 5d 0c 11 05 07 94 13 0f 11 05 07 11 05 08 94 9e 11 05 08 11 0f 9e 11 05 11 05 07 94 11 05 08 94 d6 20 00 01 00 00 5d 94 13 10 02 11 08 17 da 17 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 16 93 13 11 11 11 28 ?? ?? ?? 0a 13 0f 11 0f 11 10 61 13 12 09 11 12 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 12 08 28 ?? ?? ?? 0a 11 08 17 da 28 ?? ?? ?? 0a 26}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "GetTempPath" ascii //weight: 1
        $x_1_5 = "ToCharArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MD_2147796700_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MD!MTB"
        threat_id = "2147796700"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 10 00 73 b6 00 00 0a ?? ?? ?? ?? 7e 9f 00 00 04 11 07 09 08 28 ?? ?? ?? 06 17 73 b7 00 00 0a 13 05 7e a1 00 00 04 11 05 11 06 16 11 06 8e 69 28 ?? ?? ?? 06 7e 81 00 00 04 11 05 28 ?? ?? ?? 06 7e 6b 00 00 04 28 ?? ?? ?? 06 13 08 7e a5 00 00 04 11 08 7e a3 00 00 04 11 04 28 ?? ?? ?? 06 28 ?? ?? ?? 06 0a de 11}  //weight: 1, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "Replace" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
        $x_1_7 = "ContainsKey" ascii //weight: 1
        $x_1_8 = "GetTempPath" ascii //weight: 1
        $x_1_9 = "LoadFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MF_2147796711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MF!MTB"
        threat_id = "2147796711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {25 16 1f 2d 9d 6f ?? ?? ?? 0a 0b 16 0c 2b 14 06 08 07 08 9a 28 ?? ?? ?? 06 28 ?? ?? ?? 06 9c 08 17 58 0c 08 06 8e 69 32 e6 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "key_register" ascii //weight: 1
        $x_1_3 = "revstring" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "DownloadData" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "professor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MF_2147796711_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MF!MTB"
        threat_id = "2147796711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "65.21.199.14" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "StringDecrypt" ascii //weight: 1
        $x_1_4 = "CreateShadowCopy" ascii //weight: 1
        $x_1_5 = "get_IP" ascii //weight: 1
        $x_1_6 = "get_Password" ascii //weight: 1
        $x_1_7 = "get_NameOfBrowser" ascii //weight: 1
        $x_1_8 = "get_Cookies" ascii //weight: 1
        $x_1_9 = "get_Credentials" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MM_2147797743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MM!MTB"
        threat_id = "2147797743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a fe 0e 02 00 fe 0c 02 00 20 00 01 00 00 6f ?? ?? ?? 0a fe 0c 02 00 20 80 ?? ?? ?? 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 20 e8 03 00 00 73 ?? ?? ?? 0a fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? 0a 20 08 ?? ?? ?? 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? 0a 20 08 ?? ?? ?? 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe 0c 02 00 20 01 00 00 00 6f 28 00 00 0a fe 0c 01 00 fe 0c 02 00 6f 29 00 00 0a 20 01 00 00 00 73 2a 00 00 0a fe 0e 04 00 fe 0c 04 00 fe 09 00 00 20 00 00 00 00 fe 09 00 00 8e 69 6f 2b 00 00 0a fe ?? ?? ?? 6f ?? ?? ?? 0a dd}  //weight: 1, accuracy: Low
        $x_1_2 = "BUY CRYPT FROM PULSAR CRYPTER - @PulsarCrypter_bot" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "CipherMode" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "set_Key" ascii //weight: 1
        $x_1_8 = "ToString" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MO_2147797745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MO!MTB"
        threat_id = "2147797745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 07 20 00 01 00 00 6f ?? ?? ?? 0a 07 20 80 00 00 00 6f ?? ?? ?? 0a 1e 8d 37 00 00 01 25 d0 7e 00 00 04 28 ?? ?? ?? 0a 0c 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 08 20 e8 03 00 00 73 ?? ?? ?? 0a 0d 07 09 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 09 07 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 17 6f ?? ?? ?? 0a 72 ?? ?? ?? 70}  //weight: 1, accuracy: Low
        $x_1_2 = {13 04 06 07 12 00 28 0b 00 00 06 28 2e 00 00 0a [0-6] 6f ?? ?? ?? 0a 17 73 30 00 00 0a 13 08 11 08 11 04 16 11 04 8e 69 6f ?? ?? ?? 0a 11 08 6f ?? ?? ?? 0a de 0c 11 08 2c 07 11 08 6f ?? ?? ?? 0a dc 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 05 14 13 06 17 8d 01 00 00 01 25 16 17 8d 2d 00 00 01 25 16 72 ?? ?? ?? 70 a2 a2 13 07 11 05 11 06 11 07 6f ?? ?? ?? 0a 26}  //weight: 1, accuracy: Low
        $x_1_3 = "ToString" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "ReverseString" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "ToArray" ascii //weight: 1
        $x_1_9 = "Invoke" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MP_2147797746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MP!MTB"
        threat_id = "2147797746"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 73 96 00 00 0a 12 00 28 ?? ?? ?? 06 28 ?? ?? ?? [0-8] 0c 73 ?? ?? ?? 0a 0d 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 06 20 e8 03 00 00 73 ?? ?? ?? 0a 13 04 09 20 00 01 00 00 6f ?? ?? ?? 0a 09 20 80 00 00 00 6f ?? ?? ?? 0a 09 11 04 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 11 04 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 17 6f ?? ?? ?? 0a 08 09 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 07 11 07 07 16 07 8e 69 6f ?? ?? ?? 0a 11 07 6f ?? ?? ?? 0a de 0c 11 07 2c 07 11 07 6f ?? ?? ?? 0a dc 14 13 05 17 8d 01 00 00 01 25 16 17 8d 2d 00 00 01 25 16 72 ?? ?? ?? 70 a2 a2 13 06 28 ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 05 11 06 6f ?? ?? ?? 0a 26 16 28 ?? ?? ?? 0a de}  //weight: 1, accuracy: Low
        $x_1_2 = "ToString" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "ReverseString" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "ToArray" ascii //weight: 1
        $x_1_8 = "Invoke" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MR_2147797748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MR!MTB"
        threat_id = "2147797748"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 73 31 01 00 0a 0b 06 72 a9 18 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0c 20 f4 01 00 00 28 ?? ?? ?? 0a 00 07 72 50 19 00 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 08 28 ?? ?? ?? 0a 72 fd 19 00 70 6f ?? ?? ?? 0a 13 04 11 04 72 45 1a 00 70 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "ToString" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
        $x_1_6 = "Invoke" ascii //weight: 1
        $x_1_7 = "get_passwd" ascii //weight: 1
        $x_1_8 = "get_login" ascii //weight: 1
        $x_1_9 = "CreateInstance" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "get_Transaction" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MS_2147797749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MS!MTB"
        threat_id = "2147797749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 16 0b 2b 26 06 02 07 6f ?? ?? ?? 0a 03 07 03 6f 84 00 00 0a 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 d1 06 6f ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "DownloadFile" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "get_Credentials" ascii //weight: 1
        $x_1_6 = "StringDecrypt" ascii //weight: 1
        $x_1_7 = "Decrypt" ascii //weight: 1
        $x_1_8 = "Sleep" ascii //weight: 1
        $x_1_9 = "FromBase64" ascii //weight: 1
        $x_1_10 = "Replace" ascii //weight: 1
        $x_1_11 = "FromBase64String" ascii //weight: 1
        $x_1_12 = "DecryptBlob" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MV_2147798018_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MV!MTB"
        threat_id = "2147798018"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a fe 0e 01 00 fe 0c 00 00 39 81 00 00 00 fe 0c 00 00 8e 39 77 00 00 00 fe 0c 00 00 73 ?? 00 00 0a fe 0e 02 00 fe 0c 02 00 20 00 00 00 00 73 ?? 00 00 0a fe 0e 03 00 fe 0c 03 00 73 ?? 00 00 0a fe 0e 04 00 fe 0c 04 00 6f ?? ?? ?? 0a fe 0e 01 00 dd 39 00 00 00 fe 0c 04 00 39 09 00 00 00 fe 0c 04 00 6f ?? ?? ?? 0a dc}  //weight: 1, accuracy: Low
        $x_1_2 = "BUY CRYP" ascii //weight: 1
        $x_1_3 = "@PulsarCrypter_bot" ascii //weight: 1
        $x_1_4 = "DecompressString" ascii //weight: 1
        $x_1_5 = "FromBase64" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "GZipStream" ascii //weight: 1
        $x_1_8 = "GetBytes" ascii //weight: 1
        $x_1_9 = "Replace" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_ML_2147798602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ML!MTB"
        threat_id = "2147798602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {de 0b 08 2c 07 08 6f ?? ?? ?? 0a 00 dc 07 6f ?? ?? ?? 0a 0d de 16 07 2c 07 07 6f ?? ?? ?? 0a 00 dc}  //weight: 1, accuracy: Low
        $x_1_2 = "MemoryStream" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "DynamicInvoke" ascii //weight: 1
        $x_1_5 = "FileLocked" ascii //weight: 1
        $x_1_6 = "RegistryRecovered" ascii //weight: 1
        $x_1_7 = "SuspendCountExceeded" ascii //weight: 1
        $x_1_8 = "PasswordRestriction" ascii //weight: 1
        $x_1_9 = "CheckRemoteDebuggerPresent" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_ML_2147798602_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ML!MTB"
        threat_id = "2147798602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a fe 0e 02 00 fe 0c 02 00 20 00 01 00 00 6f ?? ?? ?? 0a fe 0c 02 00 20 80 00 00 00 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 20 e8 03 00 00 73 23 00 00 0a fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? 0a 20 08 00 00 00 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? 0a 20 08 00 00 00 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe ?? ?? ?? 20 01 00 00 00 6f ?? ?? ?? 0a fe ?? ?? ?? fe ?? ?? ?? 6f ?? ?? ?? 0a 20 01 00 00 00 73 2b 00 00 0a fe ?? ?? ?? fe ?? ?? ?? fe ?? ?? ?? 20 00 00 00 00 fe ?? ?? ?? 8e 69 6f ?? ?? ?? 0a fe ?? ?? ?? 6f ?? ?? ?? 0a dd 13 00 00 00 fe ?? ?? ?? 39 09 00 00 00 fe ?? ?? ?? 6f ?? ?? ?? 0a dc fe 0c 01 00 6f ?? ?? ?? 0a fe}  //weight: 1, accuracy: Low
        $x_1_2 = "BUY CRYPT FROM PULSAR CRYPTER - @PulsarCrypter_bot" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "CipherMode" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "set_Key" ascii //weight: 1
        $x_1_8 = "ToString" ascii //weight: 1
        $x_1_9 = "set_Password" ascii //weight: 1
        $x_1_10 = "CheckRemoteDebuggerPresent" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAB_2147798604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAB!MTB"
        threat_id = "2147798604"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 0a 28 0b ?? ?? 0a 7e ?? 00 00 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 7e ?? 00 00 04 6f ?? ?? ?? 0a 20 e8 03 00 00 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 00 08 20 00 01 00 00 6f ?? ?? ?? 0a 00 08 07 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 07 08 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 73 ?? 00 00 0a 0d 00 09 08 6f ?? ?? ?? 0a 17 73 ?? 00 00 0a 13 04 00 11 04 02 16 02 8e 69 6f ?? ?? ?? 0a 00 11 04 6f ?? ?? ?? 0a 00 00 de 14 11 04 14 fe 01 13 06 11 06 2d 08 11 04 6f ?? ?? ?? 0a 00 dc 00 09 6f ?? ?? ?? 0a 0a 00 de}  //weight: 1, accuracy: Low
        $x_1_2 = "payload" ascii //weight: 1
        $x_1_3 = "Decrypt" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "set_KeySize" ascii //weight: 1
        $x_1_9 = "get_KeySize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAD_2147799133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAD!MTB"
        threat_id = "2147799133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 2d 07 16 8d ?? 00 00 01 2a 02 16 91 18 63 19 5f 0a 06 17 2e 0f 06 19 2e 0b 72 ?? ?? ?? 70 73 ?? 00 00 0a 7a 02 28 ?? ?? ?? 06 0b 02 28 ?? ?? ?? 06 0c 16 0d 17 13 04 07 8d ?? 00 00 01 13 05 20 00 10 00 00 8d ?? 00 00 01 13 06 20 00 10 00 00 8d ?? 00 00 01 13 07 07 1c 59 1a 59 17 59 13 08 15 13 09 16 13 0a 02 16 91 17 5f 17 2e 1b 07 8d ?? 00 00 01 13 0b 02 02 28 ?? ?? ?? 06 11 0b 16 07 28 ?? ?? ?? 0a 11 0b 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 08 91 02 08 17 58 91 1e 62 60 02 08 18 58 91 1f 10 62 60 02 08 19 58 91 1f 18 62 60 13 04 08 1a 58 0c 09 11 08 30 3b 06 17 33 18 02 08 91 02 08 17 58 91 1e 62 60 02 08 18 58 91 1f 10 62 60 13 0a 2b 1f}  //weight: 1, accuracy: High
        $x_1_3 = "Decompress" ascii //weight: 1
        $x_1_4 = "SizeDecompressed" ascii //weight: 1
        $x_1_5 = "HeaderLength" ascii //weight: 1
        $x_1_6 = "Sleep" ascii //weight: 1
        $x_1_7 = "WriteAllBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAE_2147799134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAE!MTB"
        threat_id = "2147799134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 1f 0f 59 8d ?? 00 00 01 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 ?? ?? ?? 0a 1f 10 8d ?? 00 00 01 0c 07 8e 69 08 8e 69 59 8d ?? 00 00 01 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28 ?? ?? ?? 0a 07 16 09 16 07 8e 69 08 8e 69 59 28 ?? ?? ?? 0a 73 ?? 00 00 06 03 06 14 09 08 28 ?? ?? ?? 06 13 04 de}  //weight: 1, accuracy: Low
        $x_1_2 = "get_IP" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "bEncryptedData" ascii //weight: 1
        $x_1_5 = "DecryptBlob" ascii //weight: 1
        $x_1_6 = "Chr_0_M_e" ascii //weight: 1
        $x_1_7 = "get_PostalCode" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
        $x_1_11 = "OsCrypt" ascii //weight: 1
        $x_1_12 = "get_encrypted_key" ascii //weight: 1
        $x_1_13 = "Decrypt" ascii //weight: 1
        $x_1_14 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAF_2147799596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAF!MTB"
        threat_id = "2147799596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BUY CRYP" ascii //weight: 1
        $x_1_2 = "@PulsarCrypter_bot" ascii //weight: 1
        $x_1_3 = "SruHCja" ascii //weight: 1
        $x_1_4 = "TJwKNwVhE" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "GetDomain" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "Wow64GetThreadContext" ascii //weight: 1
        $x_1_9 = "GetThreadContext" ascii //weight: 1
        $x_1_10 = "ReadProcessMemory" ascii //weight: 1
        $x_1_11 = "WriteProcessMemory" ascii //weight: 1
        $x_1_12 = "SetThreadContext" ascii //weight: 1
        $x_1_13 = "DynamicDllInvoke" ascii //weight: 1
        $x_1_14 = "DynamicDllModule" ascii //weight: 1
        $x_1_15 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAH_2147799598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAH!MTB"
        threat_id = "2147799598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 8e 69 17 59 32 db 11 04 6f ?? ?? ?? 0a 2d 58 12 00 7b ?? 00 00 04 6f ?? ?? ?? 0a 2d 4a 28 ?? ?? ?? 0a 12 00 7b ?? 00 00 04 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 16 13 08 2b 25 09 11 08 9a 08 28 ?? ?? ?? 0a 2c 10 1b 39 ?? ?? ?? ff 09 11 08 17 58 9a 13 04 2b 12 11 08 1d 2c a5 18 58 13 08 11 08 09 8e 69 17 59 32 d2 11 04 6f ?? ?? ?? 0a 16 3e}  //weight: 1, accuracy: Low
        $x_1_2 = {13 04 11 04 11 07 09 08 6f ?? ?? ?? 0a 17 73 ?? 00 00 0a 13 05 11 05 11 06 16 11 06 8e 69 6f ?? ?? ?? 0a 11 05 6f ?? ?? ?? 0a 1c 2c ce 28 ?? ?? ?? 0a 13 08 11 08 11 04 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a de 0f 1b 2c 04 11 07 2c 07 11 07 6f ?? ?? ?? 0a dc}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "CreateEncryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "Replace" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "FlushFinalBlock" ascii //weight: 1
        $x_1_11 = "GetTempPath" ascii //weight: 1
        $x_1_12 = "get_Length" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAK_2147799599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAK!MTB"
        threat_id = "2147799599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 07 02 07 0e 04 0e 04 8e 69 12 04 11 06 11 06 8e 69 14 18 28 ?? ?? ?? 06 12 07 18 28 ?? ?? ?? 06 28 ?? ?? ?? 06 2c 03 16 2b 03 17 2b 00 2d 06 73 ?? 00 00 0a 7a 11 07 8d ?? 00 00 01 0d 02 07 0e 04 0e 04 8e 69 12 04 11 06 11 06 8e 69 09 09 8e 69 12 07 18 28 ?? ?? ?? 06 28 ?? ?? ?? 06 25 1f 14 28 ?? ?? ?? 06 33 06 73 ?? 00 00 0a 7a 2c 03 16 2b 03 17 2b 00 2d 06 73 ?? 00 00 0a 7a de}  //weight: 1, accuracy: Low
        $x_1_2 = "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO" ascii //weight: 1
        $x_1_3 = "EncryptedData" ascii //weight: 1
        $x_1_4 = "DecryptBlob" ascii //weight: 1
        $x_1_5 = "get_UserName" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "get_KeySize" ascii //weight: 1
        $x_1_8 = "FromBase64" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
        $x_1_11 = "CreateDecryptor" ascii //weight: 1
        $x_1_12 = "GetBytes" ascii //weight: 1
        $x_1_13 = "get_Credentials" ascii //weight: 1
        $x_1_14 = "CryptDecrypt" ascii //weight: 1
        $x_1_15 = "get_encrypted_key" ascii //weight: 1
        $x_1_16 = "ChromeGetName" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAL_2147799600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAL!MTB"
        threat_id = "2147799600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 8e 69 1e 5a 6f ?? ?? ?? 0a 00 11 05 02 7b ?? 00 00 04 6f ?? ?? ?? 0a 00 11 05 02 7b ?? 00 00 04 8e 69 1e 5a 6f ?? ?? ?? 0a 00 11 05 02 7b ?? 00 00 04 6f ?? ?? ?? 0a 00 11 05 6f ?? ?? ?? 0a 13 06 00 03 73 ?? 00 00 0a 13 07 00 11 07 11 06 16 73 ?? 00 00 0a 13 08 00 03 8e 69 17 59 17 58 17 59 17 58 8d ?? 00 00 01 13 09 11 08 11 09 16 03 8e 69 6f ?? ?? ?? 0a 13 0a 11 09 11 0a 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0c 00 de}  //weight: 1, accuracy: Low
        $x_1_2 = "cipher" ascii //weight: 1
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
        $x_1_6 = "FlushFinalBlock" ascii //weight: 1
        $x_1_7 = "WriteByte" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
        $x_1_9 = "FromBase64" ascii //weight: 1
        $x_1_10 = "ophthalmologic" ascii //weight: 1
        $x_1_11 = "get_Script" ascii //weight: 1
        $x_1_12 = "get_Hosts" ascii //weight: 1
        $x_1_13 = "set_KeySize" ascii //weight: 1
        $x_1_14 = "set_IV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAN_2147805563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAN!MTB"
        threat_id = "2147805563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 63 00 64 00 6e 00 2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f 00 61 00 74 00 74 00 61 00 63 00 68 00 6d 00 65 00 6e 00 74 00 73 00 2f 00 [0-96] 2f 00 6d 00 69 00 63 00 72 00 69 00 66 00 69 00 65 00 73 00 2e 00 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 73 3a 2f 2f 63 64 6e 2e 64 69 73 63 6f 72 64 61 70 70 2e 63 6f 6d 2f 61 74 74 61 63 68 6d 65 6e 74 73 2f [0-96] 2f 6d 69 63 72 69 66 69 65 73 2e 6a 70 67}  //weight: 1, accuracy: Low
        $x_1_3 = "THE_INTERACTION" ascii //weight: 1
        $x_1_4 = "SUPER_LOKER" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "DebuggableAttribute" ascii //weight: 1
        $x_1_7 = "Picture Puzzle" ascii //weight: 1
        $x_1_8 = "DownloadString" ascii //weight: 1
        $x_1_9 = "NR_DetroitSatar" ascii //weight: 1
        $x_1_10 = "get_sinfoniettas" ascii //weight: 1
        $x_1_11 = {e0 12 17 13 de 12 14 13 14 13 e7 12 e5 12 04 13 11 13 e0 12 f1 12 0f 13 16 13 e4 12 de 12 20 00 49 00 6e 00 63 00 2e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (10 of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAT_2147806285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAT!MTB"
        threat_id = "2147806285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AdScWJCZxvG" wide //weight: 1
        $x_1_2 = "05a3b992-a730-4177-a0cb-f70344535615" ascii //weight: 1
        $x_1_3 = "Dy*|/nam*|/icDl*|/lInvo*|/ke" wide //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "GetDomain" ascii //weight: 1
        $x_1_6 = "CRYPTOAPI_BLOB" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "Kill" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAV_2147807763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAV!MTB"
        threat_id = "2147807763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "prkPQQdiCsc" ascii //weight: 1
        $x_1_2 = "vaOpeljCSOxsJWNohFQm" ascii //weight: 1
        $x_1_3 = "CryptoConvert" ascii //weight: 1
        $x_1_4 = "Kill" ascii //weight: 1
        $x_1_5 = "GetDomain" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_8 = "ReadProcessMemory" wide //weight: 1
        $x_1_9 = "VirtualAllocEx" wide //weight: 1
        $x_1_10 = "WriteProcessMemory" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAW_2147807764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAW!MTB"
        threat_id = "2147807764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 0d 16 06 6f ?? ?? ?? 0a 25 26 11 0e 6a 59 69 6f ?? ?? ?? 0a 25 26 26 11 0a 11 0d 16 06 6f ?? ?? ?? 0a 25 26 11 0e 6a 59 69 6f ?? ?? ?? 0a 25 26 13 10 7e ?? ?? ?? 04 11 10 16 11 10 28 ?? ?? ?? 06 25 26 69 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 0b 07 16 6a 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 0c 11 04 1e 5f 39}  //weight: 1, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "ReduceConfig" ascii //weight: 1
        $x_1_7 = "ReduceDatabase" ascii //weight: 1
        $x_1_8 = "RunPE" ascii //weight: 1
        $x_1_9 = "MemoryEvent" ascii //weight: 1
        $x_1_10 = "Reverse" ascii //weight: 1
        $x_1_11 = "set_IV" ascii //weight: 1
        $x_1_12 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MW_2147808463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MW!MTB"
        threat_id = "2147808463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 31 00 33 00 2e 00 32 00 31 00 32 00 2e 00 38 00 38 00 2e 00 [0-9] 2f 00 56 00 76 00 2f 00 72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 2e 00 6a 00 73 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 3a 2f 2f 31 31 33 2e 32 31 32 2e 38 38 2e [0-9] 2f 56 76 2f 72 65 73 6f 75 72 63 65 2e 6a 73 6f 6e}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\Windows\\SysWOW64\\svchost.exe" ascii //weight: 1
        $x_1_4 = "C:\\Windows\\SysWOW64\\rundll32.exe" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "DownloadFile" ascii //weight: 1
        $x_1_7 = "Sleep" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "ToString" ascii //weight: 1
        $x_1_10 = "get_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MX_2147808464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MX!MTB"
        threat_id = "2147808464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 02 7b ?? ?? ?? 04 8e 69 1e d8 6f ?? ?? ?? 0a 00 11 05 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 11 05 02 7b ?? ?? ?? 04 8e 69 1e d8 6f ?? ?? ?? 0a 00 11 05 02 7b ?? ?? ?? 04 6f ?? ?? ?? 0a 00 11 05 6f ?? ?? ?? 0a 13 06 00 03 73 ?? ?? ?? 0a 13 07 00 11 07 11 06 16 73 ?? ?? ?? 0a 13 08 00 03 8e 69 17 da 17 d6 17 da 17 d6 8d ?? 00 00 01 13 09 11 08 11 09 16 03 8e 69 6f ?? ?? ?? 0a 13 0a 11 09 11 0a 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 13 04 00 de}  //weight: 1, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "cipher" ascii //weight: 1
        $x_1_5 = "get_Email" ascii //weight: 1
        $x_1_6 = "get_UserType" ascii //weight: 1
        $x_1_7 = "DebuggerBrowsableAttribute" ascii //weight: 1
        $x_1_8 = "get_Key" ascii //weight: 1
        $x_1_9 = "FromBase64" ascii //weight: 1
        $x_1_10 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MZ_2147808465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MZ!MTB"
        threat_id = "2147808465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 2c 13 7e ?? 00 00 04 02 6f 28 00 00 0a 74 ?? 00 00 01 0c de 5b 73 ?? 00 00 0a 0a 16 0b 2b 27 06 02 07 6f ?? ?? ?? 0a 7e 01 00 00 04 07 7e 01 00 00 04 8e 69 5d 91 61 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 d0 7e 02 00 00 04 02 06 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0c de}  //weight: 1, accuracy: Low
        $x_1_2 = "ContainsKey" ascii //weight: 1
        $x_1_3 = "ToString" ascii //weight: 1
        $x_1_4 = "Sleep" ascii //weight: 1
        $x_1_5 = "PushQueue" ascii //weight: 1
        $x_1_6 = "TestQueue" ascii //weight: 1
        $x_1_7 = "ComputeQueue" ascii //weight: 1
        $x_1_8 = "DownloadData" ascii //weight: 1
        $x_1_9 = "GetBytes" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAA_2147808467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAA!MTB"
        threat_id = "2147808467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 0d 20 04 00 00 00 28 ?? ?? ?? 06 3a cb ff ff ff 26 20 02 00 00 00 38 c0 ff ff ff 00 00 11 0d 11 07 28 0c 00 00 06 17 73 0b 00 00 0a 13 04 20 00 00 00 00 28 ?? ?? ?? 06 39 0a 00 00 00 26 38 00 00 00 00 fe 0c 0a 00 45 03 00 00 00 19 00 00 00 05 00 00 00 13 01 00 00 38 14 00 00 00 00 11 0d 28 ?? ?? ?? 06 13 0b 20 02 00 00 00 38 d6 ff ff ff 00 00 11 04 02 16 02 8e 69 6f ?? ?? ?? 0a 20 01 00 00 00 28 ?? ?? ?? 06 3a 0f 00 00 00 26 20 01 00 00 00 38}  //weight: 1, accuracy: Low
        $x_1_2 = {26 38 ca fd ff ff 00 11 07 11 01 11 07 6f 0d 00 00 0a 1e 5b 28 09 00 00 06}  //weight: 1, accuracy: High
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "MemoryStream" ascii //weight: 1
        $x_1_6 = "set_KeySize" ascii //weight: 1
        $x_1_7 = "get_KeySize" ascii //weight: 1
        $x_1_8 = "get_BlockSize" ascii //weight: 1
        $x_1_9 = "Crypted" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "set_IV" ascii //weight: 1
        $x_1_12 = "FromBase64" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAC_2147808546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAC!MTB"
        threat_id = "2147808546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 0c 8d 66 00 00 01 25 d0 d9 00 00 04 28 ?? ?? ?? 0a 0a 02 19 06 16 1f 0c 28 ?? ?? ?? 0a 02 8e 69 1f 0f 59 8d 66 00 00 01 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 ?? ?? ?? 0a 1f 10 8d 66 00 00 01 0c 07 8e 69 08 8e 69 59 8d 66 00 00 01 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28 ?? ?? ?? 0a 07 16 09 16 07 8e 69 08 8e 69 59 28 ?? ?? ?? 0a 73 ?? 00 00 06 03 06 14 09 08 28 ?? ?? ?? 06 13 04 de}  //weight: 1, accuracy: Low
        $x_1_2 = "ScanPasswords" ascii //weight: 1
        $x_1_3 = "ScanCook" ascii //weight: 1
        $x_1_4 = "DecryptBlob" ascii //weight: 1
        $x_1_5 = "Chr_0_M_e" ascii //weight: 1
        $x_1_6 = "get_PostalCode" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = "GetBytes" ascii //weight: 1
        $x_1_11 = "get_os_crypt" ascii //weight: 1
        $x_1_12 = "get_Key" ascii //weight: 1
        $x_1_13 = "moz_cookies" ascii //weight: 1
        $x_1_14 = "DecryptChromium" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAG_2147808550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAG!MTB"
        threat_id = "2147808550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 8e 69 1f 0f 59 8d ?? 00 00 01 0b 02 1f 0f 07 16 02 8e 69 1f 0f 59 28 ?? ?? ?? 0a 1f 10 8d ?? 00 00 01 0c 07 8e 69 08 8e 69 59 8d ?? 00 00 01 0d 07 07 8e 69 1f 10 59 08 16 1f 10 28 ?? ?? ?? 0a 07 16 09 16 07 8e 69 08 8e 69 59 28 ?? ?? ?? 0a 73 ?? 00 00 06 03 06 14 09 08 6f ?? ?? ?? 06 13 04 de}  //weight: 1, accuracy: Low
        $x_1_2 = "Decrypt" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "get_UserDomainName" ascii //weight: 1
        $x_1_7 = "Reverse" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "TryGetConnection" ascii //weight: 1
        $x_1_11 = "get_Credentials" ascii //weight: 1
        $x_1_12 = "CryptDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAI_2147808551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAI!MTB"
        threat_id = "2147808551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "127f8e8b-2551-483f-80f7-bc8614061c41" ascii //weight: 1
        $x_1_2 = "Hotspot Shield 7.9.0" ascii //weight: 1
        $x_1_3 = "Onhydelroqwmtywoiwqz" ascii //weight: 1
        $x_1_4 = "powershell" ascii //weight: 1
        $x_1_5 = "Test-Connection" ascii //weight: 1
        $x_1_6 = "google" ascii //weight: 1
        $x_1_7 = "facebook" ascii //weight: 1
        $x_1_8 = "InvokeMember" ascii //weight: 1
        $x_1_9 = "GetBytes" ascii //weight: 1
        $x_1_10 = "CreateDecryptor" ascii //weight: 1
        $x_1_11 = "RijndaelManaged" ascii //weight: 1
        $x_1_12 = "MemoryStream" ascii //weight: 1
        $x_1_13 = "CipherMode" ascii //weight: 1
        $x_1_14 = "CryptoStream" ascii //weight: 1
        $x_1_15 = "set_KeySize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_FB_2147808805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.FB!MTB"
        threat_id = "2147808805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DebuggerNonUserCodeAttribute" ascii //weight: 3
        $x_3_2 = "HelpKeywordAttribute" ascii //weight: 3
        $x_3_3 = "VIRUS_DOWNLOADED_AS_STRING" ascii //weight: 3
        $x_3_4 = "WEBCLIENT_TO_DOWNLOAD_VIRUS" ascii //weight: 3
        $x_3_5 = "Local_STORED_VIRUS" ascii //weight: 3
        $x_3_6 = "System.Security.Cryptography" ascii //weight: 3
        $x_3_7 = "Stone Quarry Hill Artpark" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAP_2147808836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAP!MTB"
        threat_id = "2147808836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BUY CRYP" wide //weight: 1
        $x_1_2 = "@PulsarCrypter_bot" wide //weight: 1
        $x_1_3 = "LKGHbTSBS" wide //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "get_Name" ascii //weight: 1
        $x_1_7 = "GetDomain" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
        $x_1_9 = "get_Size" ascii //weight: 1
        $x_1_10 = "get_Controls" ascii //weight: 1
        $x_1_11 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_12 = "GetThreadContext" wide //weight: 1
        $x_1_13 = "ReadProcessMemory" wide //weight: 1
        $x_1_14 = "WriteProcessMemory" wide //weight: 1
        $x_1_15 = "SetThreadContext" wide //weight: 1
        $x_1_16 = "DynamicDllInvoke" wide //weight: 1
        $x_1_17 = "DynamicDllModule" wide //weight: 1
        $x_1_18 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAR_2147808839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAR!MTB"
        threat_id = "2147808839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "874761e7-6f4e-4d1a-93ab-64d73e5fb210" ascii //weight: 1
        $x_1_2 = "A*|/sse*|/mblyBui*|/lderAc*|/cess" wide //weight: 1
        $x_1_3 = "WNCGEUqUOGP" ascii //weight: 1
        $x_1_4 = "aVbNYouoNgyKvguLFfps" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "Kill" ascii //weight: 1
        $x_1_8 = "GetDomain" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
        $x_1_10 = "DynamicDllModule" wide //weight: 1
        $x_1_11 = "DynamicDllInvoke" wide //weight: 1
        $x_1_12 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_13 = "ReadProcessMemory" wide //weight: 1
        $x_1_14 = "WriteProcessMemory" wide //weight: 1
        $x_1_15 = "ResumeThread" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAZ_2147809190_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAZ!MTB"
        threat_id = "2147809190"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 0d 6a 59 13 05 20 00 09 69 8d ?? ?? ?? 01 25 17 28 ?? ?? ?? 06 13 04 06 28 ?? ?? ?? 06 [0-6] 07 06 11 04 11 05 09 6f ?? ?? ?? 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "IsLogging" ascii //weight: 1
        $x_1_3 = "Sleep" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "Debugger" ascii //weight: 1
        $x_1_9 = "sdfsd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAX_2147809310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAX!MTB"
        threat_id = "2147809310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NaolqKrhljT" ascii //weight: 1
        $x_1_2 = "GetDomain" ascii //weight: 1
        $x_1_3 = "eOcCTwerizGVqXZhsLsZ" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "Replace" ascii //weight: 1
        $x_1_6 = "Wow64GetThreadContext" wide //weight: 1
        $x_1_7 = "ReadProcessMemory" wide //weight: 1
        $x_1_8 = "VirtualAllocEx" wide //weight: 1
        $x_1_9 = "WriteProcessMemory" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MAY_2147809312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MAY!MTB"
        threat_id = "2147809312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 0d 16 06 6f ?? ?? ?? 0a 25 26 11 0e 6a 59 69 6f ?? ?? ?? 0a 25 26 26 11 0a 11 0d 16 06 6f ?? ?? ?? 0a 25 26 11 0e 6a 59 69 6f ?? ?? ?? 0a 25 26 13 10 7e ?? ?? ?? 04 11 10 16 11 10 28 ?? ?? ?? 06 25 26 69 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 0b 07 16 6a 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 0c 11 04 1e 5f 39}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "DeleteWindow" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "TransformBlock" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
        $x_1_9 = "PublishQueue" ascii //weight: 1
        $x_1_10 = "RunPE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MCA_2147810298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MCA!MTB"
        threat_id = "2147810298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 04 11 04 07 2f 00 09 20 00 01 00 00 6f ?? ?? ?? 0a 00 09 20 80 00 00 00 6f ?? ?? ?? 0a 00 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a [0-6] 20 e8 03 00 00 73 ?? ?? ?? 0a 13 05 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 11 05 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 09 17 6f ?? ?? ?? 0a 00 08 09 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 13 06 00 11 06 03 16 03 8e 69 6f ?? ?? ?? 0a 00 11 06 6f ?? ?? ?? 0a 00 00 de}  //weight: 1, accuracy: Low
        $x_1_2 = "Sleep" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "Mones" ascii //weight: 1
        $x_1_9 = "GetBytes" ascii //weight: 1
        $x_1_10 = "set_KeySize" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MDA_2147810508_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MDA!MTB"
        threat_id = "2147810508"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 6f 89 00 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 28 ?? ?? ?? 06 28 ?? ?? ?? 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "GetBytes" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "FlushFinalBlock" ascii //weight: 1
        $x_1_7 = "DebuggableAttribute" ascii //weight: 1
        $x_1_8 = "base64EncodedData" ascii //weight: 1
        $x_1_9 = "set_Key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MGA_2147811461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MGA!MTB"
        threat_id = "2147811461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Buy & sell Crypto in minutes, join the world" ascii //weight: 1
        $x_1_2 = "largest crypto exchange" ascii //weight: 1
        $x_1_3 = "SkipSecurityChecksRemotingServices" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "/9PAw4fxuPprSD" ascii //weight: 1
        $x_1_6 = "DebuggerStepperBoundaryAttributegetMD" ascii //weight: 1
        $x_1_7 = "get_ProxyRevalidate" ascii //weight: 1
        $x_1_8 = "LockedFromBaseString" ascii //weight: 1
        $x_1_9 = "KoreanEraEndProlog" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MHA_2147811462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MHA!MTB"
        threat_id = "2147811462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateEncryptor" ascii //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "cmdaaaaaaaaa.exe" wide //weight: 1
        $x_1_4 = "kmIagokrSm" wide //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "ToBase64String" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MIA_2147811463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MIA!MTB"
        threat_id = "2147811463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bgfdfgdf.exe" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "GetHINSTANCE" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "WriteLine" ascii //weight: 1
        $x_1_8 = "FromBase64String" ascii //weight: 1
        $x_1_9 = "GetBytes" ascii //weight: 1
        $x_1_10 = "DownloadString" ascii //weight: 1
        $x_1_11 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MJA_2147811464_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MJA!MTB"
        threat_id = "2147811464"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a fe 0e 07 00 7e 01 00 00 04 3a 40 00 00 00 20 00 00 00 00 72 01 00 00 70 14 d0 01 00 00 02 28 ?? ?? ?? 0a 20 01 00 00 00 8d 47 00 00 01 25 20 00 00 00 00 20 00 00 00 00 14 28 20 00 00 0a a2 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 80 01 00 00 04 7e 01 00 00 04 7b 2a 00 00 0a 7e 01 00 00 04 fe 0c 06 00 6f ?? ?? ?? 0a fe 0e 01 00 dd}  //weight: 1, accuracy: Low
        $x_1_2 = {0a fe 0e 01 00 fe 0c 00 00 39 dc 02 00 00 fe 0c 00 00 8e 39 d2 02 00 00 fe 0c 00 00 73 1a 00 00 0a fe 0e 02 00 7e 06 00 00 04 3a 28 00 00 00 20 00 00 00 00 d0 09 00 00 01 28 ?? ?? ?? 0a d0 01 00 00 02 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 80 06 00 00 04 7e 06 00 00 04 7b 1e 00 00 0a 7e 06 00 00 04 fe 0c 02 00 6f ?? ?? ?? 0a fe}  //weight: 1, accuracy: Low
        $x_1_3 = "DecompressString" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "MARWA" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "GZipStream" ascii //weight: 1
        $x_1_8 = "CompressionMode" ascii //weight: 1
        $x_1_9 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_RPN_2147811605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.RPN!MTB"
        threat_id = "2147811605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BCrLPWStryptOpeLPWStrnAlgorithmProviLPWStrder" wide //weight: 1
        $x_1_2 = "BCstring.EmptyryptSstring.EmptyetPrstring.Emptyoperstring.Emptyty" wide //weight: 1
        $x_1_3 = "Armenia" wide //weight: 1
        $x_1_4 = "Kyrgyzstan" wide //weight: 1
        $x_1_5 = "api.ip.sb" wide //weight: 1
        $x_1_6 = "Profile_encrypted_value" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MLA_2147811906_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MLA!MTB"
        threat_id = "2147811906"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FI7hCt7Zgwx" ascii //weight: 1
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_1_4 = "MarshalCookieIsPersistent" ascii //weight: 1
        $x_1_5 = "FileWritableTypeIA" ascii //weight: 1
        $x_1_6 = "MemoryStreamINVOKE" ascii //weight: 1
        $x_1_7 = "SoapServicessetKeyPassword" ascii //weight: 1
        $x_1_8 = "DebuggableAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_RPC_2147812380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.RPC!MTB"
        threat_id = "2147812380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "cmd /c timeout 20" wide //weight: 1
        $x_1_3 = "ZszzDowZszznlZszzoadDZszzataZszz" wide //weight: 1
        $x_1_4 = "81.4.105.174" wide //weight: 1
        $x_1_5 = "Sifican.log" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MQA_2147812731_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MQA!MTB"
        threat_id = "2147812731"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 08 13 05 14 13 08 11 05 8e 69 1e 5b 13 0c 11 05 73 ?? 00 00 0a 73 ?? 00 00 06 13 0d 16 13 16 38 23 00 00 00 11 0d 6f ?? ?? ?? 06 13 17 11 0d 6f ?? ?? ?? 06 13 18 11 04 11 17 11 18 6f ?? ?? ?? 0a 11 16 17 58 13 16 11 16 11 0c 3f d4 ff ff ff 11 0d 6f ?? ?? ?? 06 11 04 80 ?? 00 00 04 dd}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "TransformBlock" ascii //weight: 1
        $x_1_6 = "Replace" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "base64EncodedData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_RPP_2147812790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.RPP!MTB"
        threat_id = "2147812790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "49.12.217.106" wide //weight: 1
        $x_1_2 = "flex.zip" wide //weight: 1
        $x_1_3 = "LinkCriate" wide //weight: 1
        $x_1_4 = "Madara" wide //weight: 1
        $x_1_5 = "SpecialFolder" ascii //weight: 1
        $x_1_6 = "FtpWebResponse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MRA_2147813152_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MRA!MTB"
        threat_id = "2147813152"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "ftp://49.12.217.106//flex.zip" wide //weight: 1
        $x_1_2 = "\\Temp\\kjasf231" wide //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
        $x_1_5 = "DebuggableAttribute" ascii //weight: 1
        $x_1_6 = "set_Credentials" ascii //weight: 1
        $x_1_7 = {01 0c 16 0d 73 ?? ?? ?? 0a 15 00 0b 20 00 08 00 00 8d 20 00 00 [0-9] 13 04 2b 0a 11 04 08 16 09 6f ?? ?? ?? 0a 07 08 16 08 8e 69 6f ?? ?? ?? 0a 25 0d 16 30 e6 11 04 6f ?? ?? ?? 0a 0a de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_AD_2147813529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.AD!MTB"
        threat_id = "2147813529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 10 2b 15 28 ?? ?? ?? ?? 2b f1 28 ?? ?? ?? ?? 2b ed 28 ?? ?? ?? ?? 2b 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {66 30 36 35 39 65 35 39 30 35 34 35 34 61 35 65 39 39 62 39 37 35 32 61 66 63 37 38 62 37 30 30 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 70 14 1e 2d 06 26 26 26 26 2b 07 2f 00 28 ?? ?? 00 06 28 ?? ?? 00 06 72 ?? ?? 00 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_AD_2147813529_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.AD!MTB"
        threat_id = "2147813529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ENCRYPTION_ECGOST" ascii //weight: 3
        $x_3_2 = "sm2encrypt" ascii //weight: 3
        $x_3_3 = "Grabber\\Discord\\Tokens.txt" wide //weight: 3
        $x_3_4 = "Exodus\\exodus.wallet" wide //weight: 3
        $x_3_5 = "CryptoWallets\\WalletForRegyster" wide //weight: 3
        $x_3_6 = "START CMD /C \"ECHO VirtualMachine Detected" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MUA_2147814039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MUA!MTB"
        threat_id = "2147814039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "openIPLog_Regid" ascii //weight: 1
        $x_1_2 = "decrypt" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "iplogger.org/1qptf7" wide //weight: 1
        $x_1_5 = "scCHG7RLwqCrFOdRmd" wide //weight: 1
        $x_1_6 = "zippedBuffer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MWA_2147814544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MWA!MTB"
        threat_id = "2147814544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bvsdvdssd" ascii //weight: 1
        $x_1_2 = "VirtualProtect" ascii //weight: 1
        $x_1_3 = "DebuggableAttribute" ascii //weight: 1
        $x_1_4 = "Invoke" ascii //weight: 1
        $x_1_5 = "ToBase64String" ascii //weight: 1
        $x_1_6 = "GetBytes" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "Debugger" ascii //weight: 1
        $x_1_9 = "IsLogging" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MYA_2147814548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MYA!MTB"
        threat_id = "2147814548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RegisterFile" ascii //weight: 1
        $x_1_2 = "BCRYPT_AUTHENTICATED_CIPHER_MODE" ascii //weight: 1
        $x_1_3 = "DecryptBlob" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "ClientCredentials" ascii //weight: 1
        $x_1_6 = "_Encrypted$" wide //weight: 1
        $x_1_7 = "QWpvd2Fucy" wide //weight: 1
        $x_1_8 = "DownloadFile" ascii //weight: 1
        $x_1_9 = "os_crypt" ascii //weight: 1
        $x_1_10 = "get_encrypted_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MZA_2147814549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MZA!MTB"
        threat_id = "2147814549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 2d 02 07 6f ?? ?? ?? 0a 03 07 03 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 0c 06 72 ?? ?? ?? 70 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32 ca 06 6f ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "BytesToStringConverted" ascii //weight: 1
        $x_1_3 = "FromBase64CharArray" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "EncryptedData" ascii //weight: 1
        $x_1_6 = "DecryptBlob" ascii //weight: 1
        $x_1_7 = "CreateInstance" ascii //weight: 1
        $x_1_8 = "MemoryStream" ascii //weight: 1
        $x_1_9 = "GetBytes" ascii //weight: 1
        $x_1_10 = "browserPaths" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MA_2147814894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MA!MTB"
        threat_id = "2147814894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 0a 16 11 0a 8e 69 6f ?? ?? ?? 0a 26 38 ?? ?? ?? ff dd ?? ?? ?? ?? 11 07 3a ?? 00 00 00 38 ?? 00 00 00 fe ?? ?? ?? 45 [0-10] 38 ?? 00 00 00 38 ?? 00 00 00 20 00 00 00 00 7e ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 00 00 00 00 38 ?? ?? ?? ff 11 07 6f ?? ?? ?? 0a 38 00 00 00 00 dc}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64CharArray" ascii //weight: 1
        $x_1_3 = "etatSdaeRteNmetsyS" ascii //weight: 1
        $x_1_4 = "Replace" ascii //weight: 1
        $x_1_5 = "base64EncodedData" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_ADA_2147815452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ADA!MTB"
        threat_id = "2147815452"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 2d 17 26 7e ?? ?? 00 04 fe 06 ?? ?? 00 06 73 ?? ?? 00 0a 25 80 ?? ?? 00 04 28 ?? ?? 00 0a 74 ?? ?? 00 01 28 ?? ?? 00 0a 72 ?? ?? 00 70 28 ?? ?? 00 06 de 03 26 de 00 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {06 25 02 7d ?? ?? 00 04 fe 06 ?? ?? 00 06 73 ?? ?? 00 0a 16 8d ?? ?? 00 01 28 ?? ?? 00 2b 2c 06 73 ?? ?? 00 0a 7a}  //weight: 1, accuracy: Low
        $x_1_3 = {12 00 fe 15 02 00 00 1b 02 6f ?? ?? 00 0a 0a de 03 26 de 00 06 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_ME_2147816213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ME!MTB"
        threat_id = "2147816213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 0d 17 11 0d 11 0c 28 ?? ?? ?? 06 13 0e 11 0e 02 1a 02 8e 69 1a 59 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 13 04 de}  //weight: 1, accuracy: Low
        $x_1_2 = {13 0d 11 0d 28 ?? ?? ?? 0a 26 11 0d 07 7b ?? ?? ?? 04 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 13 0e 11 0e 28 ?? ?? ?? 0a 2d 2d 11 0e 28 ?? ?? ?? 0a 25 11 0b 16 11 0b 8e 69 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 11 0e 14 1a}  //weight: 1, accuracy: Low
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "GetBytes" ascii //weight: 1
        $x_1_5 = "GetTempPath" ascii //weight: 1
        $x_1_6 = "CreateEncryptor" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "TransformFinalBlock" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "MemoryStream" ascii //weight: 1
        $x_1_11 = "Secure System Shell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_AH_2147816514_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.AH!MTB"
        threat_id = "2147816514"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {01 57 fd 03 3c 09 0f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 84 00 00 00 fc}  //weight: 3, accuracy: High
        $x_3_2 = "is tampered." wide //weight: 3
        $x_3_3 = "Debugger Detected" wide //weight: 3
        $x_3_4 = "{11111-22222-50001-00000}" wide //weight: 3
        $x_3_5 = "{11111-22222-40001-00002}" wide //weight: 3
        $x_3_6 = "=a=b=c=d=fegeheiejekele" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MG_2147819019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MG!MTB"
        threat_id = "2147819019"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 17 58 13 05 11 05 06 6f ?? ?? ?? 0a 18 5b 32 b5 08 20 ?? ?? ?? 7f 13 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 08 16 20 ?? ?? ?? 7f 13 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = "host_watch" wide //weight: 1
        $x_1_3 = "can_shutdown" wide //weight: 1
        $x_1_4 = "send & erase content" wide //weight: 1
        $x_1_5 = "SendData" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
        $x_1_7 = "CreateDecryptor" ascii //weight: 1
        $x_1_8 = "SuspendThread" ascii //weight: 1
        $x_1_9 = "ResumeThread" ascii //weight: 1
        $x_1_10 = "IsSuspended" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MH_2147819020_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MH!MTB"
        threat_id = "2147819020"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 11 0d 16 06 6f ?? ?? ?? 0a 11 0e 6a 59 69 6f ?? ?? ?? 0a 26 11 0a 11 0d 16 06 6f ?? ?? ?? 0a 11 0e 6a 59 69 6f ?? ?? ?? 0a 13 10 7e ?? ?? ?? 04 11 10 16 11 10 8e 69 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 0b 07 16 6a}  //weight: 1, accuracy: Low
        $x_1_2 = "TransformFinalBlock" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "MemoryStream" ascii //weight: 1
        $x_1_5 = "IsDebuggerPresent" wide //weight: 1
        $x_1_6 = "OLLYDBG" wide //weight: 1
        $x_1_7 = "DynamicInvoke" ascii //weight: 1
        $x_1_8 = "GetBytes" ascii //weight: 1
        $x_1_9 = "Reverse" ascii //weight: 1
        $x_1_10 = "HidePciture" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_SDVF_2147819502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.SDVF!MTB"
        threat_id = "2147819502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 16 18 01 00 0c 2b 13 00 07 08 20 00 01 00 00 28 ?? ?? ?? 06 0b 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d e2}  //weight: 1, accuracy: Low
        $x_1_2 = "GothicCheckers" wide //weight: 1
        $x_1_3 = "BadApple" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_VV_2147820477_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.VV!MTB"
        threat_id = "2147820477"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/c timeout /nobreak /t" ascii //weight: 1
        $x_1_2 = "37.0.11.164" ascii //weight: 1
        $x_1_3 = "GetResponse" ascii //weight: 1
        $x_1_4 = "HttpWebRequest" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "Reverse" ascii //weight: 1
        $x_1_7 = "Renevct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NEA_2147822240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NEA!MTB"
        threat_id = "2147822240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 02 03 7e 06 00 00 04 5d 91 0a 16 0b 2b 00 06 ?? ?? ?? ?? ?? 03 04 5d ?? ?? ?? ?? ?? 61 0c 2b 00 08 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 03 17 58 ?? ?? ?? ?? ?? 5d 91 0a 16 13 05 2b 00 16 0b 16 13 06 2b 00 02 03 1f 16 ?? ?? ?? ?? ?? 0c 06 04 58 0d 08 09 59 04 5d 0b 16 13 07 2b 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NT_2147822309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NT!MTB"
        threat_id = "2147822309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 9f a2 2b 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 da 00 00 00 4d 00 00 00 c3 01 00 00 df 01 00 00 aa 01 00 00 13 00 00 00 95 01 00 00 07 00 00 00 b8 00 00 00 08 00 00 00 8d 00 00 00 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NTW_2147822310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NTW!MTB"
        threat_id = "2147822310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fafffgfffffff" wide //weight: 1
        $x_1_2 = "ssssssssssssssss" wide //weight: 1
        $x_1_3 = "bytes frgffffom" wide //weight: 1
        $x_1_4 = "ffsdfsdfds" wide //weight: 1
        $x_1_5 = "bytes frfffom" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NL_2147822314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NL!MTB"
        threat_id = "2147822314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {03 1f 55 61 d1 2a 3a 03 0f 02 28 29 00 00 0a 28 2a 00 00 0a 2a}  //weight: 5, accuracy: High
        $x_1_2 = "GetProcAddress" ascii //weight: 1
        $x_1_3 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NL_2147822314_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NL!MTB"
        threat_id = "2147822314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 02 06 8f 3f ?? ?? ?? 25 4b 03 06 95 61 54 00 06 17 59 0a 06 16 fe 04 16 fe 01 0b 07}  //weight: 5, accuracy: Low
        $x_5_2 = {00 02 06 8f 2d ?? ?? ?? 25 47 03 06 91 61 d2 52 00 06 17 59 0a 06 16 fe 04 16 fe 01 0b 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NL_2147822314_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NL!MTB"
        threat_id = "2147822314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6b 6f 69 00 4b 6f 61 73 6f 66 6b 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = "DebuggableAttribute" ascii //weight: 1
        $x_1_3 = "LzmaDecoder" ascii //weight: 1
        $x_1_4 = {00 52 65 73 6f 6c 76 65 45 76 65 6e 74 41 72 67 73 00 53 79 73 74 65 6d 00 44 65 63 6f 6d 70 72 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 4d 61 69 6e 00 52 65 73 6f 6c 76 65 00}  //weight: 1, accuracy: High
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_7 = "ToBase64String" ascii //weight: 1
        $x_1_8 = "ResolveMethod" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NJ_2147823232_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NJ!MTB"
        threat_id = "2147823232"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aasdasdasddassjdsudabshadad" wide //weight: 1
        $x_1_2 = "RijndaelManaged" ascii //weight: 1
        $x_1_3 = "CreateEncryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "OahaYo" ascii //weight: 1
        $x_1_6 = "a4f035e90403" ascii //weight: 1
        $x_1_7 = {9f b6 2b 09 0e 00 00 00 9a 00 23 00 06 00 00 01 00 00 00 7d 00 00 00 bc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NEC_2147823573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NEC!MTB"
        threat_id = "2147823573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 03 07 03 6f ?? ?? ?? ?? 5d 6f ?? ?? ?? ?? 06 07 91 61 d2 9c 00 07 17 58 0b 07 06 8e 69 fe 04 0c 08 2d da}  //weight: 1, accuracy: Low
        $x_1_2 = {00 18 0a 04 28 e7 01 00 0a 0b 07 72 a4 0b 00 70 6f e8 01 00 0a 0c 08 2c 06 00 06 17 59 0a 00 03 07 06 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NED_2147823574_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NED!MTB"
        threat_id = "2147823574"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 6f 25 ?? ?? ?? 03 07 03 6f ?? ?? ?? ?? 5d 6f ?? ?? ?? ?? 61 0c 06 72 ?? ?? ?? ?? 08 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 26 07 17 58 0b 07 02 6f ?? ?? ?? ?? 32 ca}  //weight: 1, accuracy: Low
        $x_1_2 = "Foamily" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_NS_2147824236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.NS!MTB"
        threat_id = "2147824236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 02 07 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 9c 07 17 58 0b 07 06 8e 69 32 e2}  //weight: 1, accuracy: Low
        $x_1_2 = "F2 D6 F6 36 E2 67 27 37 16 47 C6 57 E2" wide //weight: 1
        $x_1_3 = "67 27 37 F2 F2 A3 07 47 47 86" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_ABD_2147824757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ABD!MTB"
        threat_id = "2147824757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 00 07 2a 17 00 00 72 01 ?? ?? 70 28 05 ?? ?? 06 0a 06 28 03 ?? ?? 06 0b}  //weight: 1, accuracy: Low
        $x_1_2 = "BufferedStream" ascii //weight: 1
        $x_1_3 = "GZipStream" ascii //weight: 1
        $x_1_4 = "WebClient" ascii //weight: 1
        $x_1_5 = "get_UtcNow" ascii //weight: 1
        $x_1_6 = "ToArray" ascii //weight: 1
        $x_1_7 = "37.0.11.164" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_ABI_2147827401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ABI!MTB"
        threat_id = "2147827401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 02 6f 97 ?? ?? 0a 0b 28 98 ?? ?? 0a 72 43 ?? ?? 70 28 46 ?? ?? 0a 0c 08 07 28 99 ?? ?? 0a 00 08 28 5c ?? ?? 0a 26 00 de 14}  //weight: 3, accuracy: Low
        $x_3_2 = {0a 02 7b 82 ?? ?? 04 02 7b 83 ?? ?? 04 17 6f 91 ?? ?? 0a 00 28 08 ?? ?? 06 6f 92 ?? ?? 0a 72 e8 ?? ?? 70 72 68 ?? ?? 70 02 7b 83 ?? ?? 04 72 9a ?? ?? 70 28 46 ?? ?? 0a 6f 93 ?? ?? 0a 00 de 0f}  //weight: 3, accuracy: Low
        $x_1_3 = "Decrypt" ascii //weight: 1
        $x_1_4 = "get_Password" ascii //weight: 1
        $x_1_5 = "ChromeCookiePath" ascii //weight: 1
        $x_1_6 = "wallet_log" ascii //weight: 1
        $x_1_7 = "GetAppDataPath" ascii //weight: 1
        $x_1_8 = "GetOutlookPasswords" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_ABJ_2147827402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ABJ!MTB"
        threat_id = "2147827402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 72 59 00 00 70 72 65 00 00 70 28 22 00 00 0a 26 2a}  //weight: 1, accuracy: High
        $x_1_2 = "disposing" ascii //weight: 1
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "InitializeComponent" ascii //weight: 1
        $x_1_5 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_ABY_2147827747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ABY!MTB"
        threat_id = "2147827747"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 2c 27 20 c5 ?? ?? 81 0a 16 0b 2b 14 02 07 6f de ?? ?? 0a 06 61 20 93 ?? ?? 01 5a 0a 07 17 58 0b 07 02 6f 5d ?? ?? 0a 32 e3 06 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "SetTermBuffer" ascii //weight: 1
        $x_1_3 = "RAMDirectory" ascii //weight: 1
        $x_1_4 = "GetAwaiter" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_A_2147838646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.A!MTB"
        threat_id = "2147838646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 04 20 00 00 00 00 6f ?? 00 00 0a fe 0c 03 00 fe 0c 02 00 5d 6f ?? 00 00 0a 6f ?? 00 00 0a 61 d2 9c}  //weight: 2, accuracy: Low
        $x_2_2 = {20 15 00 00 00 58 d2 6f}  //weight: 2, accuracy: High
        $x_1_3 = "GetDomain" ascii //weight: 1
        $x_1_4 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_C_2147838648_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.C!MTB"
        threat_id = "2147838648"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 06 0a 06 28 ?? 00 00 0a 7d ?? 00 00 04 06 02 7d ?? 00 00 04 06 15 7d ?? 00 00 04 06 7c ?? 00 00 04 12 00 28 ?? 00 00 2b 06 7c}  //weight: 2, accuracy: Low
        $x_2_2 = {03 04 61 2a}  //weight: 2, accuracy: High
        $x_2_3 = {03 04 5d 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_SPQP_2147840013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.SPQP!MTB"
        threat_id = "2147840013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 0a 11 0a 6f ?? ?? ?? 0a 72 01 00 00 70 28 ?? ?? ?? 0a 2c 14 11 0a 16 8c 28 00 00 01 14 6f ?? ?? ?? 0a 26 dd 1b ff ff ff 12 09 28 ?? ?? ?? 0a 2d c7}  //weight: 2, accuracy: Low
        $x_1_2 = "Zuemilhqhym.Properties.Resources" wide //weight: 1
        $x_1_3 = "Rphkkgmxctifneqyuec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EB_2147840082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EB!MTB"
        threat_id = "2147840082"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Discord\\Local Storage\\leveldb" wide //weight: 1
        $x_1_2 = "HjgiRDU5JRg9KmcUICQsJiE7PUkcBipBNwc1Xw==" wide //weight: 1
        $x_1_3 = "Owler.exe" wide //weight: 1
        $x_1_4 = "*wallet*" wide //weight: 1
        $x_1_5 = "net.tcp" wide //weight: 1
        $x_1_6 = "localhost" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EB_2147840082_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EB!MTB"
        threat_id = "2147840082"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Valve\\SteamLogin Data" wide //weight: 1
        $x_1_2 = "NordVpn.exe*MyGToMyGkens.tMyGxt" wide //weight: 1
        $x_1_3 = "BTEAACELMVE/IDBVOj9VRCgJJUUpDz1ROiROdw==" wide //weight: 1
        $x_1_4 = "Gz0LRQ4MIlY=" wide //weight: 1
        $x_1_5 = "encrypted_key" wide //weight: 1
        $x_1_6 = "Blowie.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_F_2147843175_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.F!MTB"
        threat_id = "2147843175"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "080l48aGZULitgNo34.NQQ8oiuE0BojERB6dZ" ascii //weight: 2
        $x_2_2 = "System.Reflection.ReflectionContext" wide //weight: 2
        $x_2_3 = "X2N2sJYhfqldsLurUo.aoJRZJWgbc52Lkluem" wide //weight: 2
        $x_2_4 = "pnXSeh4c9sWhq7wkZ3.Og0aBUo3LWee8uisL1" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_SPD_2147843339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.SPD!MTB"
        threat_id = "2147843339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 7e 1c 00 00 04 06 91 20 b0 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e 1c 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 5, accuracy: High
        $x_1_2 = "MadeConnectionString" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EM_2147844421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EM!MTB"
        threat_id = "2147844421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {0a 02 8e 69 1b 59 8d 42 00 00 01 0b 02 1b 07 16 02 8e 69 1b 59 28 9f 00 00 0a 00 07 16 14 28 40 00 00 2b 0c 06 06 03 6f a0 00}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EM_2147844421_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EM!MTB"
        threat_id = "2147844421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {72 fc a1 01 70 72 00 a2 01 70 6f 3e 01 00 0a 72 04 a2 01 70 72 08 a2 01 70 6f 3e 01 00 0a 0b 73 3f 01 00 0a 0c 07 6f 40 01 00 0a 18 da 13 06 16 13 07 2b 1e 08 07 11 07 18 6f 41 01 00 0a 1f 10 28 42 01 00 0a b4 6f 43 01 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EM_2147844421_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EM!MTB"
        threat_id = "2147844421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {0a 06 72 55 84 01 70 72 f9 11 00 70 6f 25 01 00 0a 72 59 84 01 70 72 5d 84 01 70 6f 25 01 00 0a 0b 73 26 01 00 0a 0c 07 6f 04 01 00 0a 18 da 13 06 16 13 07 2b 1e 08 07 11 07 18 6f 27 01 00 0a 1f 10 28 28 01 00 0a b4 6f 29 01 00 0a 00 11 07 18 d6 13 07 11 07 11 06 31 dc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EM_2147844421_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EM!MTB"
        threat_id = "2147844421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lpProcesnoitceScitsongaiDnoitarugifnoCledoMecivreSmetsyS91469" ascii //weight: 1
        $x_1_2 = "HostToNetworkOrder" ascii //weight: 1
        $x_1_3 = "NetworkToHostOrder" ascii //weight: 1
        $x_1_4 = "Confuser.Core 1.6.0+447341964f" ascii //weight: 1
        $x_1_5 = "Autarky.exe" ascii //weight: 1
        $x_1_6 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EM_2147844421_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EM!MTB"
        threat_id = "2147844421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lpProcesdnammoCetaerCdnammoCetaerCBDIsdohteMevitaNefasnUnommoCataDmetsyS98124" ascii //weight: 1
        $x_1_2 = "Confuser.Core 1.6.0+447341964f" ascii //weight: 1
        $x_1_3 = "HttpUtility" ascii //weight: 1
        $x_1_4 = "HttpServerUtility" ascii //weight: 1
        $x_1_5 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_6 = "Chevron.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EM_2147844421_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EM!MTB"
        threat_id = "2147844421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dnlibDotNetPdb" ascii //weight: 1
        $x_1_2 = "encrypted_key" ascii //weight: 1
        $x_1_3 = "autofillProfilesTotal of RAMVPEntity12N" ascii //weight: 1
        $x_1_4 = "windows-1251, CommandLine" ascii //weight: 1
        $x_1_5 = "Replaceluemoz_cookies" ascii //weight: 1
        $x_1_6 = "net.tcp://" ascii //weight: 1
        $x_1_7 = "AntiFileSystemSpyWFileSystemareProFileSystemduct" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EM_2147844421_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EM!MTB"
        threat_id = "2147844421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Gl.h3.resources" ascii //weight: 1
        $x_1_2 = "PictureGame.Resources.resources" ascii //weight: 1
        $x_1_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_4 = "HideModuleNameAttribute" ascii //weight: 1
        $x_1_5 = "HelpKeywordAttribute" ascii //weight: 1
        $x_1_6 = "/c rmdir /Q /S" wide //weight: 1
        $x_1_7 = "Priscilla_Taylor" wide //weight: 1
        $x_1_8 = "mJUInX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EH_2147846777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EH!MTB"
        threat_id = "2147846777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CxcTED09NhA9LwoFKyYwRSgnLho" wide //weight: 1
        $x_1_2 = "Jyo2EREoTlg=" wide //weight: 1
        $x_1_3 = "net.tcp://" wide //weight: 1
        $x_1_4 = "localhost" wide //weight: 1
        $x_1_5 = "Confuser.Core" ascii //weight: 1
        $x_1_6 = "os_crypt" ascii //weight: 1
        $x_1_7 = "encrypted_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_EH_2147846777_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.EH!MTB"
        threat_id = "2147846777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 07 6f 2f 00 00 0a 03 07 03 6f 55 00 00 0a 5d 6f 2f 00 00 0a 61 0c 06 72 75 08 00 70 08 28 a0 00 00 0a 6f a1 00 00 0a 26 00 07 17 58 0b 07 02 6f 55 00 00 0a fe 04 0d 09 2d c4}  //weight: 5, accuracy: High
        $x_1_2 = "BCrhKeyyptDeshKeytroyKhKeyey" wide //weight: 1
        $x_1_3 = "AppFile.WriteData\\RoamiFile.Writeng" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_B_2147846840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.B!MTB"
        threat_id = "2147846840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 04 08 16 07 16 1f 10 28 ?? 00 00 06 7e ?? 00 00 04 08 16 07 1f 0f 1f 10 28 ?? 00 00 06 7e ?? 00 00 04 06 07 28 ?? 00 00 06 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 03 16 03 8e 69 28}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 04 08 1f 20 28 ?? 00 00 06 28 ?? 00 00 06 20 00 03 1e 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 73 ?? 00 00 0a 0c 7e ?? 00 00 04 07 7e}  //weight: 2, accuracy: Low
        $x_2_3 = {06 16 06 8e 69 28 d0 00 00 06 7e ?? 00 00 04 11 04 28 d3 00 00 06 de 1b 00 09 7e ?? 00 00 04 07 28 ?? 00 00 06 17 73 ?? 00 00 0a 13 04 7e ?? 00 00 04 11 04}  //weight: 2, accuracy: Low
        $x_2_4 = {08 03 02 20 16 20 00 00 17 09 6f ?? 00 00 0a 11 04 17 18 6f}  //weight: 2, accuracy: Low
        $x_1_5 = "GetTempPath" ascii //weight: 1
        $x_1_6 = "ManagementObjectSearcher" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_G_2147849279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.G!MTB"
        threat_id = "2147849279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "555555555555555555555d444444444444444444444A333333333333333333o222222222222222L1111111111111" wide //weight: 2
        $x_2_2 = {f6 00 63 00 df 00 75 00 6a 00 73 00 6e 00 66 00 6a 00 f6 00 6a 00 67 00 69 00 e4 00 45 00 32 00 6e 00 6b 00 79 00 df 00 70 00 fc 00 66 00 df 00 73 00 f6 00 fc 00 fc 00 65 00 75 00 75 00 31 00}  //weight: 2, accuracy: High
        $x_2_3 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_I_2147850679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.I!MTB"
        threat_id = "2147850679"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 16 06 8e 69 28 ?? 00 00 06 13 05 16 2d 18 7e}  //weight: 2, accuracy: Low
        $x_2_2 = "hdffffhfasdkfsh" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_GK_2147853229_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.GK!MTB"
        threat_id = "2147853229"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UPlRTxsojvoUKyY0hk.GYMnI7gQeQEeu4Om6t" ascii //weight: 1
        $x_1_2 = "s05AUpDFWLlXHdHxXq.oivCwUJSNiehmVIOAh" ascii //weight: 1
        $x_1_3 = "Corral.g.resources" ascii //weight: 1
        $x_1_4 = "Recycle Bio Lab Tool" ascii //weight: 1
        $x_1_5 = "Confuser.Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_KAE_2147896426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.KAE!MTB"
        threat_id = "2147896426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 11 1c 8f ?? 00 00 01 25 4a 11 05 11 1c 11 1d 28 31 00 00 0a 58 54}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_AX_2147896585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.AX!MTB"
        threat_id = "2147896585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 2f 00 00 70 28 0a ?? ?? 06 1d 3a 43 ?? ?? 00 26 20 00 ?? ?? 00 7e 33 ?? ?? 04 7b 44 ?? ?? 04 39 c9 ?? ?? ff 26 20 00 ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {69 18 3a 17 ?? ?? 00 26 26 26 38 0a ?? ?? 00 38 e7 ?? ?? ff 38 e2 ?? ?? ff 38 dd ?? ?? ff 28 35 ?? ?? 0a 38 e7 ?? ?? ff 2c 00 02 16 02 8e}  //weight: 1, accuracy: Low
        $x_1_3 = "HttpWebResponse" ascii //weight: 1
        $x_1_4 = "WebResponse" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "PushVal" ascii //weight: 1
        $x_1_7 = "37.0.11.164" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_AW_2147896627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.AW!MTB"
        threat_id = "2147896627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 28 07 6f 60 ?? ?? 0a 28 d3 ?? ?? 06 2d 1b 07 6f 60 ?? ?? 0a 28 62 ?? ?? 0a 2d 0e 07 6f 60 ?? ?? 0a 6f d2 ?? ?? 0a 0c de 31 06 6f 03 ?? ?? 0a 2d bb 45 00 06 6f 5f ?? ?? 0a 0b 07 6f 60 ?? ?? 0a 6f 61 ?? ?? 0a 18}  //weight: 1, accuracy: Low
        $x_1_2 = {72 ab 0f 00 70 20 98 3a 00 00 28 d5 00 00 06 0c de 0b}  //weight: 1, accuracy: High
        $x_1_3 = "GetTempFileName" ascii //weight: 1
        $x_1_4 = "ChromeGetName" ascii //weight: 1
        $x_1_5 = "Reverse" ascii //weight: 1
        $x_1_6 = "GetFolderPath" ascii //weight: 1
        $x_1_7 = "GetGraphicCards" ascii //weight: 1
        $x_1_8 = "GetDirectories" ascii //weight: 1
        $x_1_9 = "GetFiles" ascii //weight: 1
        $x_1_10 = "get_GatewayAddresses" ascii //weight: 1
        $x_1_11 = "browserPaths" ascii //weight: 1
        $x_1_12 = "FromBase64CharArray" ascii //weight: 1
        $x_1_13 = "chromeKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_KAF_2147898341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.KAF!MTB"
        threat_id = "2147898341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 0c 06 72 ?? ?? 00 70 08 28 ?? ?? 00 0a 6f ?? ?? 00 0a 26 07 17 58 0b 07 02 6f ?? 00 00 0a 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_KAG_2147900005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.KAG!MTB"
        threat_id = "2147900005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 9c 06 08 91 06 09 91 58 20 00 ?? 00 00 5d 13 07 02 11 05 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 07 91 61 d2 81 ?? 00 00 01 11 05 17 58 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_K_2147900028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.K!MTB"
        threat_id = "2147900028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "CryptoHelper" ascii //weight: 2
        $x_2_2 = "StringDecrypt" ascii //weight: 2
        $x_2_3 = "DeviceMonitor" ascii //weight: 2
        $x_2_4 = "IPv4Helper" ascii //weight: 2
        $x_2_5 = "SystemInfoHelper" ascii //weight: 2
        $x_2_6 = "BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO" ascii //weight: 2
        $x_2_7 = "BCRYPT_KEY_LENGTHS_STRUCT" ascii //weight: 2
        $x_2_8 = "BCRYPT_OAEP_PADDING_INFO" ascii //weight: 2
        $x_2_9 = "BCRYPT_PSS_PADDING_INFO" ascii //weight: 2
        $x_2_10 = "FileCopier" ascii //weight: 2
        $x_2_11 = "FileScannerRule" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_KAH_2147900311_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.KAH!MTB"
        threat_id = "2147900311"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a2 07 08 9a 7e ?? 00 00 04 28 ?? ?? 00 06 08 17 58 0c 08 07 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_LA_2147901473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.LA!MTB"
        threat_id = "2147901473"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 09 11 06 9c 06 08 91 06 09 91 58 ?? ?? ?? ?? ?? 5d 13 07 02 11 05 8f 1d ?? ?? ?? 25 ?? ?? ?? ?? ?? 06 11 07 91 61 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_LB_2147901674_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.LB!MTB"
        threat_id = "2147901674"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 04 03 05 66 60 61 58 0e 07 0e 04 e0 95 58 7e 38 29 ?? ?? 0e 06 17 59 e0 95 58 0e 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_MY_2147901834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.MY!MTB"
        threat_id = "2147901834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0a 1f 20 8d ?? 00 00 01 0b 03 19 73 ?? ?? ?? 0a 0c 08 07 16 07 8e 69 6f ?? ?? ?? 0a 26 73 ?? ?? ?? 0a 0d 09 20 00 01 00 00 6f ?? ?? ?? 0a 09 20 80 00 00 00 6f ?? ?? ?? 0a 06 07 20 50 c3 00 00 73 ?? ?? ?? 0a 13 04 09 11 04 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 11 04 09 6f ?? ?? ?? 0a 1e 5b 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 09 18 6f ?? ?? ?? 0a 09 1a 6f ?? ?? ?? 0a 08 09 6f ?? ?? ?? 0a 16 73 ?? ?? ?? 0a 13 05 28 ?? ?? ?? 0a 72 0b 03 00 70 28 ?? ?? ?? 0a 13 06 11 06 18 73 ?? ?? ?? 0a 13 07 20 ?? ?? ?? 00 8d ?? 00 00 01 13 09 2b 11 28 ?? ?? ?? 0a 11 07 11 09 16 11 08 6f ?? ?? ?? 0a 11 05 11 09 16 11 09 8e 69 6f ?? ?? ?? 0a 25 13 08 16 30}  //weight: 1, accuracy: Low
        $x_1_2 = "GetBytes" ascii //weight: 1
        $x_1_3 = "Base64Decoder" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "AES_Decrypt" ascii //weight: 1
        $x_1_6 = "AES_Encrypt" ascii //weight: 1
        $x_1_7 = "CreateEncryptor" ascii //weight: 1
        $x_1_8 = "mykey123" ascii //weight: 1
        $x_1_9 = "Sleep" ascii //weight: 1
        $x_1_10 = "Encoding" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_KAI_2147903586_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.KAI!MTB"
        threat_id = "2147903586"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 0d 8f ?? 00 00 01 25 71 ?? 00 00 01 07 11 11 91 61 d2}  //weight: 1, accuracy: Low
        $x_1_2 = {11 12 11 13 11 13 09 58 9e 11 13 17 58 13 13 11 13 11 12 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_KAJ_2147904102_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.KAJ!MTB"
        threat_id = "2147904102"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 09 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 0d 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_L_2147904325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.L!MTB"
        threat_id = "2147904325"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DetectEmulation" ascii //weight: 2
        $x_2_2 = "ScanAndKill" ascii //weight: 2
        $x_2_3 = "ApplicationRunningOnVirtualMachine" ascii //weight: 2
        $x_2_4 = "ApplicationRunningOnSandbox" ascii //weight: 2
        $x_2_5 = "HideOsThreads" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_SPDP_2147904390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.SPDP!MTB"
        threat_id = "2147904390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 7e 01 00 00 04 6f ?? ?? ?? 06 8e 69 20 ?? ?? ?? 00 1f 40 28 ?? ?? ?? 06 0a 16 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_KAK_2147904598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.KAK!MTB"
        threat_id = "2147904598"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 0a 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 ?? 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_KAL_2147904665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.KAL!MTB"
        threat_id = "2147904665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {05 11 12 8f ?? 00 00 01 25 71 ?? 00 00 01 11 ?? 11 ?? 91 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_M_2147905364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.M!MTB"
        threat_id = "2147905364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 ff a2 3f 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 cb 00 00 00 88 00 00 00 2c 01 00 00 64 02}  //weight: 2, accuracy: High
        $x_1_2 = "os_crypt" ascii //weight: 1
        $x_1_3 = "encrypted_key" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_N_2147906572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.N!MTB"
        threat_id = "2147906572"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 25 16 1f ?? 9d 6f ?? 00 00 0a 13 05 16 13 06}  //weight: 2, accuracy: Low
        $x_2_2 = {25 23 00 00 00 00 00 00 3e 40 28 ?? 00 00 0a 6f ?? 00 00 0a 00 25 16 6f ?? 00 00 0a 00 25 73 ?? 00 00 0a 25 20 66 0c a8 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_SDDF_2147907067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.SDDF!MTB"
        threat_id = "2147907067"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {5d 0b 08 11 04 07 91 58 20 00 01 00 00 5d 0c 16 13 10}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_O_2147910478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.O!MTB"
        threat_id = "2147910478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 1f 57 59 d2 81 ?? 00 00 01 00 07 17 58 0b 07 06 fe 04 0c 08 2d}  //weight: 2, accuracy: Low
        $x_1_2 = "_crypted" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_RP_2147910585_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.RP!MTB"
        threat_id = "2147910585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 7e 69 00 00 04 28 22 01 00 06 10 01 72 1b 05 00 70 03 72 31 05 00 70 28 7c 00 00 0a 0b 28 31 01 00 06 07 73 d7 00 00 0a 72 35 05 00 70 28 d8 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_RP_2147910585_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.RP!MTB"
        threat_id = "2147910585"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "39"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "get_TransactionStrategy" ascii //weight: 1
        $x_1_2 = "NotImplementedException" ascii //weight: 1
        $x_1_3 = "set_TransactionStrategy" ascii //weight: 1
        $x_1_4 = "get_LazyLoading" ascii //weight: 1
        $x_1_5 = "set_LazyLoading" ascii //weight: 1
        $x_1_6 = "get_CacheDLR" ascii //weight: 1
        $x_1_7 = "set_CacheDLR" ascii //weight: 1
        $x_1_8 = "get_IsolateLoadingOfModule" ascii //weight: 1
        $x_1_9 = "set_IsolateLoadingOfModule" ascii //weight: 1
        $x_1_10 = "get_ModuleIsolationRecipe" ascii //weight: 1
        $x_1_11 = "set_ModuleIsolationRecipe" ascii //weight: 1
        $x_1_12 = "get_CancelIfCantIsolate" ascii //weight: 1
        $x_1_13 = "set_CancelIfCantIsolate" ascii //weight: 1
        $x_1_14 = "get_Cts" ascii //weight: 1
        $x_1_15 = "set_Cts" ascii //weight: 1
        $x_1_16 = "get_LoaderSyncLimit" ascii //weight: 1
        $x_1_17 = "set_LoaderSyncLimit" ascii //weight: 1
        $x_1_18 = "get_PeImplementation" ascii //weight: 1
        $x_1_19 = "set_PeImplementation" ascii //weight: 1
        $x_1_20 = "get_LibName" ascii //weight: 1
        $x_1_21 = "remove_ConventionChanged" ascii //weight: 1
        $x_1_22 = "remove_NewProcAddress" ascii //weight: 1
        $x_1_23 = "get_DynCfg" ascii //weight: 1
        $x_1_24 = "get_UseCallingContext" ascii //weight: 1
        $x_1_25 = "set_UseCallingContext" ascii //weight: 1
        $x_1_26 = "get_UseByRef" ascii //weight: 1
        $x_1_27 = "set_UseByRef" ascii //weight: 1
        $x_1_28 = "get_TrailingArgs" ascii //weight: 1
        $x_1_29 = "set_TrailingArgs" ascii //weight: 1
        $x_1_30 = "get_RefModifiableStringBuffer" ascii //weight: 1
        $x_1_31 = "set_RefModifiableStringBuffer" ascii //weight: 1
        $x_1_32 = "get_SignaturesViaTypeBuilder" ascii //weight: 1
        $x_1_33 = "set_SignaturesViaTypeBuilder" ascii //weight: 1
        $x_1_34 = "get_TryEvaluateContext" ascii //weight: 1
        $x_1_35 = "set_TryEvaluateContext" ascii //weight: 1
        $x_1_36 = "get_ManageNativeStrings" ascii //weight: 1
        $x_1_37 = "set_ManageNativeStrings" ascii //weight: 1
        $x_1_38 = "get_BoxingControl" ascii //weight: 1
        $x_1_39 = "set_BoxingControl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_AMAC_2147918783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.AMAC!MTB"
        threat_id = "2147918783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 5d 08 58 13 16 11 16 08 5d 13 17 07 11 17 91}  //weight: 2, accuracy: High
        $x_1_2 = {09 8e 69 5d 09 8e 69 58 13}  //weight: 1, accuracy: High
        $x_2_3 = {07 11 1a 91 13 1b 11 1b 11 12 61 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_PPBH_2147926677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.PPBH!MTB"
        threat_id = "2147926677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 16 13 04 38 ?? 00 00 00 08 11 04 07 11 04 91 09 11 04 09 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_SKJ_2147926919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.SKJ!MTB"
        threat_id = "2147926919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {19 8d 4e 00 00 01 25 16 0f 01 28 26 00 00 0a 9c 25 17 0f 01 28 27 00 00 0a 9c 25 18 0f 01 28 28 00 00 0a 9c 0b 02 07 04 28 02 00 00 2b 6f 2b 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_2 = {16 0a 2b 0e 02 03 04 06 05 28 0b 00 00 06 06 17 58 0a 06 02 28 08 00 00 06 2f 09 03 6f 2e 00 00 0a 05 32 e0}  //weight: 1, accuracy: High
        $x_1_3 = "lblBrojPogodaka" ascii //weight: 1
        $x_1_4 = "FluentLog4Net.Properties.Resources" ascii //weight: 1
        $x_1_5 = "LOTO_aplikacija.FrmLoto.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_PQBH_2147927613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.PQBH!MTB"
        threat_id = "2147927613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {39 00 00 0a 0a 06 72 ?? 00 00 70 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 06 72 ?? 00 00 70 28 ?? ?? ?? ?? 6f ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 0b 14 0c 38 12 00 00 00 00 28 ?? ?? ?? ?? 0c dd 06 00 00 00 26 dd 00 00 00 00 08 2c eb 07 08 16 08 8e 69 6f ?? ?? ?? ?? 0d dd}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_SKKP_2147929089_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.SKKP!MTB"
        threat_id = "2147929089"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {25 16 11 13 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 13 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 13 20 ff 00 00 00 5f d2 9c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_AMCW_2147929312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.AMCW!MTB"
        threat_id = "2147929312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 25 16 12 ?? 28 ?? 00 00 0a 9c 25 17 12 ?? 28 ?? 00 00 0a 9c 25 18 12 ?? 28 ?? 00 00 0a 9c 11 ?? 28}  //weight: 4, accuracy: Low
        $x_1_2 = {1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 ?? 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 ?? 20 ff 00 00 00 5f d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedLineStealer_ZOR_2147946264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedLineStealer.ZOR!MTB"
        threat_id = "2147946264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedLineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 03 04 6f ?? 00 00 0a 0a 12 01 fe ?? 13 00 00 02 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 12 00 28 ?? 00 00 0a 7d ?? 00 00 04 12 01 07 7b ?? 00 00 04 20 80 00 00 00 59 6c 07 7b ?? 00 00 04 20 80 00 00 00 59}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

