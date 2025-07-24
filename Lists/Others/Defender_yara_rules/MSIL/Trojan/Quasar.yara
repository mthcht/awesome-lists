rule Trojan_MSIL_Quasar_DHE_2147743350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.DHE!MTB"
        threat_id = "2147743350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 02 8e 69 5d 02 07 02 8e 69 5d 91 06 07 06 8e 69 5d 91 61 28 ?? ?? ?? ?? 02 07 17 58 02 8e 69 5d 91 28 ?? ?? ?? ?? 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? ?? 9c 07 17 58 0b 07 02 8e 69 31 bb}  //weight: 1, accuracy: Low
        $x_1_2 = "Invoke" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_PA_2147752001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.PA!MTB"
        threat_id = "2147752001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ENABLELOGGER" ascii //weight: 1
        $x_1_2 = "HIDELOGDIRECTORY" ascii //weight: 1
        $x_1_3 = "HandleGetKeyloggerLogs" ascii //weight: 1
        $x_1_4 = "HandleDoAskElevate" ascii //weight: 1
        $x_1_5 = "HandleDoProcessKill" ascii //weight: 1
        $x_1_6 = "GetSavedPasswords" ascii //weight: 1
        $x_1_7 = "QuasarRAT-master" ascii //weight: 1
        $x_1_8 = "CaptureScreen" ascii //weight: 1
        $x_1_9 = "HandleDoUploadAndExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_PB_2147752004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.PB!MTB"
        threat_id = "2147752004"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "grabber_video" wide //weight: 1
        $x_1_2 = "grabber_snapshot" wide //weight: 1
        $x_1_3 = "GetKeyloggerLogs" ascii //weight: 1
        $x_1_4 = "Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_5 = "Opera Software\\Opera Stable\\Login Data" wide //weight: 1
        $x_1_6 = "Yandex\\YandexBrowser\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_7 = "DoWebcamStop" ascii //weight: 1
        $x_1_8 = "DoProcessKill" ascii //weight: 1
        $x_1_9 = "DoStartupItemAdd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_DA_2147787597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.DA!MTB"
        threat_id = "2147787597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? ?? ?? 0a 06 08 17 58 06 8e 69 5d 91 28 ?? ?? ?? 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 0a 9c 00 08 15 58 0c 08 16 fe 04 16 fe 01 0d 09 2d b4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_ZA_2147810491_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.ZA!MTB"
        threat_id = "2147810491"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$3C374A42-BAE4-11CF-BF7D-00AA006946EE" ascii //weight: 1
        $x_1_2 = "DeflateStream" ascii //weight: 1
        $x_1_3 = "GatewayIPAddressInformationCollection" ascii //weight: 1
        $x_1_4 = "DESCryptoServiceProvider" ascii //weight: 1
        $x_1_5 = "RSACryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "System.Security.Cryptography.X509Certificates" ascii //weight: 1
        $x_1_7 = "Client.Tests" ascii //weight: 1
        $x_1_8 = {00 63 6f 6d 70 49 42 4d 26 26 00}  //weight: 1, accuracy: High
        $x_1_9 = "Rfc2898DeriveBytes" ascii //weight: 1
        $x_1_10 = "DebuggableAttribute" ascii //weight: 1
        $x_1_11 = "DebuggerNonUserCodeAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_N_2147818869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.N!MTB"
        threat_id = "2147818869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 15 a2 09 09 1f 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 37 00 00 00 0b 00 00 00 0a 00 00 00 20 00 00 00 07 00 00 00 44 00 00 00 51 00 00 00 10}  //weight: 1, accuracy: High
        $x_1_2 = "22-eaf84818aab5" ascii //weight: 1
        $x_1_3 = "108.anonfiles.com/D9h3P3Pex2/e0f0a67c-1647857705/ino" ascii //weight: 1
        $x_1_4 = "claim.Resource" ascii //weight: 1
        $x_1_5 = "DeleteFile" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_DC_2147828942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.DC!MTB"
        threat_id = "2147828942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 ff b6 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 49 01 00 00 2b}  //weight: 10, accuracy: High
        $x_1_2 = "xClient.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "CreateInstance" ascii //weight: 1
        $x_1_4 = "Base64String" ascii //weight: 1
        $x_1_5 = "GetTypes" ascii //weight: 1
        $x_1_6 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_SB_2147829236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.SB!MTB"
        threat_id = "2147829236"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 08 11 07 08 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 06 7b ?? ?? ?? ?? 11 07 91 61 d2 9c 00 11 07 17 58 13 07 11 07 06 7b ?? ?? ?? ?? 8e 69 fe 04 13 08 11 08 2d c3}  //weight: 10, accuracy: Low
        $x_1_2 = "gH5mlOFBw1z4TnYXPUbsuy2yuNOUva9TjnJJQ6fA2X0" ascii //weight: 1
        $x_1_3 = "L28MM8HKBMQ799X" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "Invoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_ROM_2147832028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.ROM!MTB"
        threat_id = "2147832028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 0a 17 8d 01 00 00 01 0c 08 16 17 8d 14 00 00 01 0d 09 a2 08 0b}  //weight: 2, accuracy: High
        $x_1_2 = "DownloadAsyncData" ascii //weight: 1
        $x_1_3 = "filebin.net" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NZQ_2147837478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NZQ!MTB"
        threat_id = "2147837478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 15 00 00 0a 0b 06 16 73 16 00 00 0a 73 17 00 00 0a 0c 08 07 6f 18 00 00 0a 07 6f 19 00 00 0a 0d de 1e}  //weight: 1, accuracy: High
        $x_1_2 = {57 15 a2 09 09 01 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 26 00 00 00 06 00 00 00 04 00 00 00 10 00 00 00 02 00 00 00 27 00 00 00 16 00 00 00 03 00 00 00 02 00 00 00 04}  //weight: 1, accuracy: High
        $x_1_3 = "WindowsFormsApp1.Properties.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MBN_2147838133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MBN!MTB"
        threat_id = "2147838133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 08 09 28 ?? ?? ?? 06 09 16 6a 6f ?? ?? ?? 0a 09 13 04 de 1c}  //weight: 1, accuracy: Low
        $x_1_2 = "$8c102025-8810-407e-9db7-9b131b499880" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQW_2147838207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQW!MTB"
        threat_id = "2147838207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 26 00 00 0a 0a 73 ?? ?? ?? 0a 0b 06 02 6f ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 0d 07 6f ?? ?? ?? 0a 09}  //weight: 5, accuracy: Low
        $x_1_2 = "tmp6171.tmp" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MA_2147838777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MA!MTB"
        threat_id = "2147838777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "SinemaOtomasyonVize.exe" ascii //weight: 10
        $x_10_2 = "QzpcXFdpbmRvd3NcXE1pY3Jvc2" wide //weight: 10
        $x_2_3 = "Caspol" ascii //weight: 2
        $x_2_4 = "Donus" ascii //weight: 2
        $x_1_5 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQE_2147840346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQE!MTB"
        threat_id = "2147840346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0b 00 00 0a 0c 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 08 16 08 8e 69 6f ?? 00 00 0a 11 05}  //weight: 5, accuracy: Low
        $x_5_2 = {72 19 24 29 70 a2 11 07 17 11 04 28 ?? ?? ?? 0a a2 11 07 13 08 11 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 20 ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_3 = "NodeType_To_XpathNodeType_Map" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MBBK_2147840355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MBBK!MTB"
        threat_id = "2147840355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 0d 00 00 0a 0a 06 28 ?? 00 00 0a 03 50 6f 0f 00 00 0a 6f 10 00 00 0a 0b 73 11 00 00 0a 0c 08 07 6f 12 00 00 0a 08 18 6f 13 00 00 0a 08 6f 14 00 00 0a 02 50 16 02 50 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQF_2147841370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQF!MTB"
        threat_id = "2147841370"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {17 59 6a 06 4b 17 58 6e 5a 31 94 0f 01 03 8e 69 17 59 28 ?? ?? ?? 2b 03 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "jSphndkg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MBBI_2147841786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MBBI!MTB"
        threat_id = "2147841786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 09 11 00 11 05 11 00 91 11 0a 61 d2 9c}  //weight: 1, accuracy: High
        $x_1_2 = "justnormalsite.ddns.net/SystemEnv/uploads/" wide //weight: 1
        $x_1_3 = {4f 00 76 00 79 00 79 00 76 00 69 00 6d 00 68 00 61 00 6a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_RF_2147842061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.RF!MTB"
        threat_id = "2147842061"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 11 08 58 20 ee 6b b4 e8 11 00 61 11 01 61 61 11 0b 11 00 20 9b e6 45 58 58 11 01 59 5f 61 13 41}  //weight: 1, accuracy: High
        $x_1_2 = {11 08 58 20 ee 6b b4 e8 11 00 61 11 01 61 61 11 0b 11 00 20 9b e6 45 58 58 11 01 59 5f 61 13 41}  //weight: 1, accuracy: High
        $x_1_3 = {11 02 11 01 1a 62 11 01 1b 63 61 11 01 58 11 03 11 00 11 03 1f 0b 63 19 5f 94 58 61 59 13 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_RF_2147842061_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.RF!MTB"
        threat_id = "2147842061"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 0f 0a 1f 0f 0b 1f 0f 0b 00 07 16 33 05 1f 0f 0b 2b 17 00 12 00 12 01 12 02 12 03 7e ?? ?? ?? ?? 06 97 29 ?? ?? ?? ?? 2b df 00 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "$5f0dccc8-d69a-49f8-9e64-61ae77bff48f" ascii //weight: 1
        $x_1_3 = "Grasyay.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_EC_2147842230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.EC!MTB"
        threat_id = "2147842230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "jkzjzwoaix.g.resources" ascii //weight: 1
        $x_1_2 = "ResourceDictionaryLocation" ascii //weight: 1
        $x_1_3 = "ResourceManager" ascii //weight: 1
        $x_1_4 = "System.Resources" ascii //weight: 1
        $x_1_5 = "cxnbvrsmrl" ascii //weight: 1
        $x_1_6 = "vriusbwvyd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQC_2147842248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQC!MTB"
        threat_id = "2147842248"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 e6 00 00 00 28 ?? 00 00 06 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 06 0b 07 74 ?? 00 00 1b 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "orthodox.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQR_2147842251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQR!MTB"
        threat_id = "2147842251"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 13 00 00 0a 0b 07 07 8e 69 18 59 28 ?? ?? 00 0a 0c 08 20 ?? ?? 00 00 fe 01 13 05 11 05 39 ?? ?? 00 00}  //weight: 5, accuracy: Low
        $x_1_2 = "SiMayService.Loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQS_2147843447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQS!MTB"
        threat_id = "2147843447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 06 07 11 06 9a 1f 10 28 ?? 00 00 0a 9c 00 11 06 17 58 13 06 11 06 07 8e 69 fe 04 13 07 11 07 3a d9 ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "bAZmT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NAS_2147843448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NAS!MTB"
        threat_id = "2147843448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {95 11 0d 1d 95 5a 9e 11 17 20 ?? ?? ?? 44 5a 20 ?? ?? ?? 4c 61 38 ?? ?? ?? ff 11 0c 1e 11 0c 1e 95 11 0d 1e 95}  //weight: 5, accuracy: Low
        $x_1_2 = "github.com/3F/Conari" ascii //weight: 1
        $x_1_3 = "RxLHX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NAS_2147843448_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NAS!MTB"
        threat_id = "2147843448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 10 00 00 0a 72 ?? 00 00 70 02 73 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 02 6f ?? 00 00 0a 0b 25 07 28 ?? 00 00 0a 28 17 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "qazwsx" wide //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQP_2147843449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQP!MTB"
        threat_id = "2147843449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0d 00 00 0a 02 6f ?? ?? ?? 0a 0a 03 18 18 73 ?? ?? ?? 0a 0b 06 07 6f 10 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "SeroXen_Dropper" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MBCO_2147843658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MBCO!MTB"
        threat_id = "2147843658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 72 05 02 00 70 72 01 00 00 70 6f ?? 00 00 0a 10 00 02 6f ?? 00 00 0a 18 5b 8d ?? 00 00 01 0a 16 0b 38 18 00 00 00 06 07 02 07 18 5a 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 07 17 58 0b 07 06 8e 69 32 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AQU_2147843998_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AQU!MTB"
        threat_id = "2147843998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 06 03 6f ?? ?? ?? 0a 0b 07 8e 16 fe 03 0c 08 2c 05 00 07 0d de 0f 14 0d de 0b 06 2c 07 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AQU_2147843998_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AQU!MTB"
        threat_id = "2147843998"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 0f 11 0f 2c 25 00 72 ?? 05 00 70 11 0e 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 00 17 13 0b ?? ?? ?? ?? ?? 00 de 05 26 00 00 de 00 00 11 0d 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MBCW_2147844200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MBCW!MTB"
        threat_id = "2147844200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 0a 06 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 0c 21 61 00 00 00 00 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {51 75 61 73 61 72 20 43 6c 69 65 6e 74 00 00 0a 01 00 05 31 2e 34 2e 30 00 00 09 15 12 84 fd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NAP_2147844510_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NAP!MTB"
        threat_id = "2147844510"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 10 00 00 0a 72 ?? 00 00 70 02 73 11 00 00 0a 28 ?? 00 00 0a 28 13 00 00 0a 28 ?? 00 00 0a 06 02 6f ?? 00 00 0a 0b 25 07 28 ?? 00 00 0a 28 17 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "deon734" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MB_2147844582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MB!MTB"
        threat_id = "2147844582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 06 1a 73 23 00 00 0a 25 07 16 07 8e 69 6f 24 00 00 0a 73 25 00 00 0a 20 00 00 9f 24 20 00 80 48 28 6f 26 00 00 0a 8d 2c 00 00 01 0c 73 25 00 00 0a 08 6f 27 00 00 0a 25 08 16 08 8e 69 6f 24 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MB_2147844582_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MB!MTB"
        threat_id = "2147844582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {57 d4 02 e8 c9 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 31 00 00 00 17 00 00 00 58 00 00 00 9e 00 00 00 47 00 00 00 11 00 00 00 01 00 00 00 03 00 00 00 15 00 00 00 02 00 00 00 03 00 00 00 0e}  //weight: 10, accuracy: High
        $x_1_2 = {6b 6f 69 00 73 65 72 76 65 72 31 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = "cc7fad03-816e-432c-9b92-001f2d358386" ascii //weight: 1
        $x_1_4 = "server1.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQD_2147845305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQD!MTB"
        threat_id = "2147845305"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 95 58 20 01 60 9f de 61 9e 11 0b 20 ?? ?? ?? 60 5a 20 ?? ?? ?? af 61 38 ?? ?? ?? ff 08 08 5a 20 ?? ?? ?? 14 6a 5e 0c 20 a7 91 bd 2d}  //weight: 5, accuracy: Low
        $x_1_2 = "jusched" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQ_2147845771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQ!MTB"
        threat_id = "2147845771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 6f 65 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 06 28 ?? 00 00 06 0d 28 ?? 00 00 06 09}  //weight: 5, accuracy: Low
        $x_1_2 = "brave.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQ_2147845771_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQ!MTB"
        threat_id = "2147845771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {17 8d 01 00 00 01 25 16 d0 ?? 00 00 01 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 75 ?? 00 00 01 14 6f ?? 00 00 0a 75 ?? 00 00 1b}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp95.Properties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQ_2147845771_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQ!MTB"
        threat_id = "2147845771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 8d 39 00 00 01 0b 06 07 16 1a 6f ?? 00 00 0a 26 07 16 28 ?? 00 00 0a 0c 06 16 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 09 11 04 16 08 6f ?? 00 00 0a 26}  //weight: 5, accuracy: Low
        $x_1_2 = "SEEDCRACKER.g.resources" ascii //weight: 1
        $x_1_3 = "Ziuxvwldnngigg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQ_2147845771_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQ!MTB"
        threat_id = "2147845771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6f 2b 00 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 7e ?? ?? ?? 04 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "PowershellExecutorXorEncoded" ascii //weight: 1
        $x_1_3 = "Client_built_hvnc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQ_2147845771_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQ!MTB"
        threat_id = "2147845771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 29 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 0a 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 0b 02 28 ?? 00 00 06 06 07 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "GetExecutableBytesWithEncrypt" ascii //weight: 1
        $x_1_3 = "StartProcessWithEncrtpt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_ABSF_2147845963_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.ABSF!MTB"
        threat_id = "2147845963"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 46 00 6f 00 72 00 6d 00 73 00 41 00 70 00 70 00 33 00 30 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 2, accuracy: High
        $x_2_2 = {4e 00 6f 00 68 00 6e 00 76 00 68 00 75 00 6e 00 6d}  //weight: 2, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQQ_2147846350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQQ!MTB"
        threat_id = "2147846350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 03 17 11 04 58 91 11 04 1e 5a 1f 1f 5f 62 58 0d 11 04 17 58 13 04 11 04 1a 3f e1 ff ff ff}  //weight: 5, accuracy: High
        $x_1_2 = "bycrpfmanhdquerp.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQQ_2147846350_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQQ!MTB"
        threat_id = "2147846350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8c 31 00 00 01 a2 11 07 18 08 28 ?? 00 00 0a a2 11 07 13 06 11 06 14 14 19 8d ?? 00 00 01 13 08 11 08 16 17 9c 11 08 17 16 9c 11 08 18 17 9c 11 08 17 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Nanysexrfmqfuikpdkhqbnegskvz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQQ_2147846350_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQQ!MTB"
        threat_id = "2147846350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 10 28 19 00 00 0a 28 ?? 00 00 0a 0b 07 07 06 25 13 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0d 09 02 1f 10 02 8e 69 1f 10 59 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Client-built.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AQ_2147846423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AQ!MTB"
        threat_id = "2147846423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 8e b7 0b 16 02 8e b7 17 da 0d 0c 2b 10 02 08 02 08 91 03 08 07 5d 91 61 9c 08 17 d6 0c 08 09 31 ec 02 0a 2b 00 06 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AQ_2147846423_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AQ!MTB"
        threat_id = "2147846423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 2b 1b 00 06 02 07 1e 6f 22 00 00 0a 18 28 23 00 00 0a 6f 24 00 00 0a 00 00 07 1e 58 0b 07 02 6f 25 00 00 0a fe 04 0c 08 2d d8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AQ_2147846423_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AQ!MTB"
        threat_id = "2147846423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 8e 69 20 00 30 00 00 1f 40 28 ?? 00 00 06 80 04 00 00 04 02 16 7e ?? 00 00 04 02 8e 69 28 ?? 00 00 0a 7e ?? 00 00 04 d0 05 00 00 02 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_PSMV_2147846449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.PSMV!MTB"
        threat_id = "2147846449"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 0c 00 00 0a 72 3d 00 00 70 28 ?? ?? ?? 0a 13 05 38 47 00 00 00 73 ?? ?? ?? 0a 25 11 05 6f ?? ?? ?? 0a 25 17 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 20 00 00 00 00 7e 10 00 00 04 7b 18 00 00 04 39 aa ff ff ff 26 20 00 00 00 00 38 9f ff ff ff 11 05 11 02 28 ?? ?? ?? 0a 38 b9 ff ff ff 11 04 72 47 00 00 70 6f ?? ?? ?? 0a 13 02 38 df ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_PSNM_2147847079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.PSNM!MTB"
        threat_id = "2147847079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 33 00 00 0a 7e 01 00 00 04 02 08 6f 34 00 00 0a 28 35 00 00 0a a5 01 00 00 1b 0b 11 07 20 85 9c 7f 3d 5a 20 4d f2 1c 75 61 38 51 fd ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NE_2147847498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NE!MTB"
        threat_id = "2147847498"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d0 09 00 00 01 28 ?? ?? ?? 0a 20 ?? ?? ?? 06 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 02 28 ?? ?? ?? 06 75 ?? ?? ?? 01 14 6f ?? ?? ?? 0a 75 ?? ?? ?? 1b 28 ?? ?? ?? 2b}  //weight: 5, accuracy: Low
        $x_1_2 = "Ztgfexus" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MAAI_2147847821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MAAI!MTB"
        threat_id = "2147847821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0c 11 1c 58 11 20 11 20 8e 69 12 00 28 ?? 00 00 06 16 fe 01 13 21 11 21 2c 06}  //weight: 1, accuracy: Low
        $x_1_2 = "b212-a41380e73785" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_GIF_2147847942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.GIF!MTB"
        threat_id = "2147847942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = "a0749986.xsph.ru" ascii //weight: 1
        $x_1_3 = "Software\\Policies\\Microsoft\\Windows\\System" ascii //weight: 1
        $x_1_4 = "\\ProgramData\\def3.exe" ascii //weight: 1
        $x_1_5 = "\\ProgramData\\AkrosAC.exe" ascii //weight: 1
        $x_1_6 = "set_UseShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NAQ_2147848622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NAQ!MTB"
        threat_id = "2147848622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 10 00 00 0a 72 ?? ?? 00 70 02 73 ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 06 02 6f ?? ?? 00 0a 0b 25 07 28 ?? ?? 00 0a 28 ?? ?? 00 0a 26}  //weight: 5, accuracy: Low
        $x_1_2 = "alkalurops.sbs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NSQ_2147849600_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NSQ!MTB"
        threat_id = "2147849600"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 10 00 00 0a 72 ?? 00 00 70 02 73 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 02 6f ?? 00 00 0a 0b 25 07 28 ?? 00 00 0a 28 ?? 00 00 0a 26}  //weight: 5, accuracy: Low
        $x_1_2 = "kXFpZBb" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MBEU_2147850244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MBEU!MTB"
        threat_id = "2147850244"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GAAACiqmcxkAAAqAAQAABHMaAAA" wide //weight: 1
        $x_1_2 = "4DJt4AEQQXWBMEEQQHb3EAAAY/c////ysLcj0" wide //weight: 1
        $x_1_3 = {70 00 72 00 69 00 76 00 61 00 74 00 65 00 2e 00 52 00 75 00 6e 00 50 00 45 00 00 07 52 00 75 00 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NW_2147850781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NW!MTB"
        threat_id = "2147850781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0c 01 00 28 ?? ?? ?? 0a 2a 20 ?? ?? ?? 00 fe ?? ?? 00 00 fe ?? ?? 00 20 ?? ?? ?? 00 fe 01 39 ?? ?? ?? 00 00 20 ?? ?? ?? 00 fe ?? ?? 00 00 fe ?? ?? 00 20 ?? ?? ?? 00 fe 01 39 ?? ?? ?? 00 38 ?? ?? ?? 00 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "gBYEBYEfull" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NVV_2147851266_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NVV!MTB"
        threat_id = "2147851266"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 10 00 00 0a 72 ?? 00 00 70 02 73 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 02 6f ?? 00 00 0a 0b 25 07 28 ?? 00 00 0a 28 ?? 00 00 0a 26 de 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "UGmbGEN" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AAGR_2147851423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AAGR!MTB"
        threat_id = "2147851423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 01 00 00 70 28 ?? 00 00 0a 0a 06 28 ?? 00 00 06 0b 07 02 28 ?? 00 00 06 0c 2b 00 08 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "KMEVtRzxG0oWl/vO4tl88v4hJcBNIzsoo8gHTKMPmoU=" wide //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MBGX_2147851426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MBGX!MTB"
        threat_id = "2147851426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nhffskdgsfkdfffddfrffffdhffscfdf" ascii //weight: 1
        $x_1_2 = "chfdfgfdkffsfhddhdshdghf" ascii //weight: 1
        $x_1_3 = "hkgfffgsdffdhdrfdfdfdsshcf" ascii //weight: 1
        $x_1_4 = "jkAaakkijferjFIFpppbmmcSidbilSkfIalcabnpojdiknnFgFilkbkFiSpfpcFkdSAikpmnbSkdirhIfebnoSmrooIbk" ascii //weight: 1
        $x_1_5 = "ggjfgssfdfh" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_PSTK_2147851863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.PSTK!MTB"
        threat_id = "2147851863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {a2 25 1a 28 09 00 00 0a 08 6f 0a 00 00 0a a2 28 0b 00 00 0a 07 28 0c 00 00 0a 20 e0 0d 00 00 28 03 00 00 0a 1f 2e 8d 03 00 00 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQU_2147852424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQU!MTB"
        threat_id = "2147852424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 62 00 00 0a 28 ?? ?? 00 0a 6f ?? ?? 00 0a 25 72 ?? ?? 00 70 02 7b ?? ?? 00 04 6f ?? ?? 00 0a 8c ?? ?? 00 01 28 ?? ?? 00 0a 6f ?? ?? 00 0a 6f ?? ?? 00 0a 7d ?? ?? 00 04 02 7b ?? ?? 00 04 6f ?? ?? 00 0a 26 02 28 ?? ?? 00 06 02 7b ?? ?? 00 04 73 ?? ?? 00 06 25 72 ?? ?? 00 70 6f ?? ?? 00 06 6f ?? ?? 00 2b}  //weight: 5, accuracy: Low
        $x_1_2 = "four.tkkkly.xyz" wide //weight: 1
        $x_1_3 = "Xtcs.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AALO_2147888228_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AALO!MTB"
        threat_id = "2147888228"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 8e 69 8d ?? 00 00 01 0b 16 0c 2b 1b 07 08 06 08 91 20 d0 71 65 cd 28 ?? 00 00 06 28 ?? 00 00 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 df}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AAMN_2147888795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AAMN!MTB"
        threat_id = "2147888795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 16 07 1f 0f 1f 10 28 ?? 00 00 06 7e ?? 00 00 04 06 07 28 ?? 00 00 06 7e ?? 00 00 04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 1b 28 ?? 00 00 06 7e ?? 00 00 04 06 28 ?? 00 00 06 0d 7e ?? 00 00 04 09 05 16 05 8e 69 28 ?? 00 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_ASFN_2147895161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.ASFN!MTB"
        threat_id = "2147895161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 09 06 8e 69 5d 7e ?? 00 00 04 06 09 06 8e 69 5d 91 08 09 08 8e 69 5d 91 61 28 ?? ?? ?? 06 06 09 17 58 06 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 09 17 58 1e 2d 50 26 09 6a 06 8e 69 17 59 6a 07 17 58 6e 5a 31}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MBEH_2147895192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MBEH!MTB"
        threat_id = "2147895192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hdffhhdfhdggfhdfdfhdjfhdasffffkdf" ascii //weight: 1
        $x_1_2 = "fghhfgjsffrfdfdfffdfdshfdsdfh" ascii //weight: 1
        $x_1_3 = "sgfjhjfffgrfhddfhfffadfsfsscfgdb" ascii //weight: 1
        $x_1_4 = "kfdfsjggfffh" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_ABNS_2147896329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.ABNS!MTB"
        threat_id = "2147896329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 16 07 16 1f 10 28 ?? ?? ?? 06 7e ?? ?? ?? 04 08 16 07 1f 0f 1f 10 28 ?? ?? ?? 06 7e ?? ?? ?? 04 06 07 28 ?? ?? ?? 06 7e ?? ?? ?? 04 06 18 28 ?? ?? ?? 06 7e ?? ?? ?? 04 06 28 ?? ?? ?? 06 0d}  //weight: 4, accuracy: Low
        $x_1_2 = "AnlfFpnimheea" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQA_2147896732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQA!MTB"
        threat_id = "2147896732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 28 fd 00 00 0a 03 04 6f ?? 00 00 0a 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 06 6f ?? 01 00 0a 2a}  //weight: 5, accuracy: Low
        $x_5_2 = {02 7b 45 00 00 04 02 02 7b ?? 00 00 04 03 28 ?? 00 00 06 6f ?? 00 00 0a 02 7b ?? 00 00 04 6f ?? 00 00 0a 17}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_NQA_2147896732_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.NQA!MTB"
        threat_id = "2147896732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 15 00 00 0a 11 04 17 11 04 8e 69 17 59 6f ?? 00 00 0a 0b 07 13 07 07 16 6f ?? 00 00 0a 1f 20 2e 0f 07 17 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 2b 07 07 6f ?? 00 00 0a 0b 07 28 ?? 00 00 06 0b 02 8e 69 16 31 1c 72 ?? 00 00 70}  //weight: 5, accuracy: Low
        $x_1_2 = "c2vahcfi" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_PSQV_2147897151_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.PSQV!MTB"
        threat_id = "2147897151"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e a6 00 00 04 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 7e a6 00 00 04 72 d6 19 00 70 72 de 19 00 70 72 ec 19 00 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 7e a6 00 00 04 6f 83 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_MG_2147899607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.MG!MTB"
        threat_id = "2147899607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 8f 26 00 00 01 25 47 07 08 07 8e 69 5d 91 61 d2 52 08 17 58 0c 08 06 8e 69 32 e3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_XZ_2147904065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.XZ!MTB"
        threat_id = "2147904065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 11 0a 74 40 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 74 40 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_ASER_2147906675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.ASER!MTB"
        threat_id = "2147906675"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {91 08 61 d2 9c 09 17 5f 17 33 07 11 0a 11 04 58 13 0a 08 1b 64 08 1f 1b 62 60 1d 5a 0c 09 17 64 09}  //weight: 2, accuracy: High
        $x_2_2 = "C:\\SELF.EXE" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AQA_2147930874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AQA!MTB"
        threat_id = "2147930874"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a2 0c 16 0d 2b 0f 07 09 9a 08 09 9a 28 ?? 00 00 06 09 17 58 0d 09 07 8e 69 32 eb 08 16 9a 28}  //weight: 2, accuracy: Low
        $x_1_2 = "45.83.244.141" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_BK_2147931309_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.BK!MTB"
        threat_id = "2147931309"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 26 08 09 6f ?? 00 00 0a 07 08 6f ?? 00 00 0a 16 73 ?? 00 00 0a 13 07 07 6f ?? 00 00 0a 1f 10 6a 59 17 6a 58 d4 8d}  //weight: 2, accuracy: Low
        $x_2_2 = {10 01 03 28 ?? ?? 00 06 10 01 03 8e 69 02 28 ?? 00 00 06 58 8d ?? 00 00 01 0a 03 8e 69 28 ?? 00 00 0a 06 02 28 ?? 00 00 06 28 ?? 00 00 0a 03 16 06 02 28 ?? 00 00 06 03 8e 69}  //weight: 2, accuracy: Low
        $x_1_3 = "GetKeyloggerLogs" wide //weight: 1
        $x_1_4 = "Get Clipboard Successfull" wide //weight: 1
        $x_1_5 = "Cant Rename The Victim" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_SWA_2147935626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.SWA!MTB"
        threat_id = "2147935626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 05 00 00 04 06 8f 03 00 00 02 03 28 10 00 00 06 0d 06 17 62 0a 06 09 58 0a 07 09 08 1f 1f 5f 62 60 0b 08 17 58 0c 08 02 7b 06 00 00 04 32 cf}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_BSA_2147935701_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.BSA!MTB"
        threat_id = "2147935701"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 00 64 00 69 00 73 00 63 00 6f 00 72 00 64 00 61 00 70 00 70 00 2e 00 63 00 6f 00 6d 00 2f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 36 00 2f 00 66 00 69 00 78 00 2d 00 43 00 68 00 65 00 61 00 74 00 5f 00 4c 00 6f 00 61 00 64 00 65 00 72 00 2e 00 62 00 61 00 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_PZMZ_2147937212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.PZMZ!MTB"
        threat_id = "2147937212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {0b 1e 8d 10 00 00 01 0c 07 28 10 00 00 0a 03 6f 11 00 00 0a 6f 12 00 00 0a 0d 09 16 08 16 1e 28 13 00 00 0a 06 08 6f 14 00 00 0a 06 18 6f 15 00 00 0a 06 18 6f 16 00 00 0a 06 6f 17 00 00 0a 13 04 02 28 18 00 00 0a 13 05 11 04 11 05 16 11 05 8e 69 6f 19 00 00 0a 13 06 28 10 00 00 0a 11 06 6f 1a 00 00 0a 13 07 dd 3a 00 00 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AUQR_2147940001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AUQR!MTB"
        threat_id = "2147940001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 06 07 28 ?? 02 00 0a 28 ?? 02 00 0a 0c 06 28 ?? 02 00 0a 3a 1a 00 00 00 06 28 ?? 03 00 0a 26 06 73 ?? 03 00 0a 25 6f ?? 04 00 0a 18 60 6f ?? 04 00 0a 08 28 ?? 02 00 0a 3a 0e 00 00 00 07 08 28 ?? 03 00 0a 08 18 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AUQ_2147944516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AUQ!MTB"
        threat_id = "2147944516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 08 11 04 6f ?? 00 00 0a de 0c 11 05 2c 07 11 05 6f ?? 00 00 0a dc 73 ?? 00 00 0a 25 11 04 6f ?? 00 00 0a 25 16 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 17 6f}  //weight: 2, accuracy: Low
        $x_5_2 = "193.151.108.34" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AQI_2147944751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AQI!MTB"
        threat_id = "2147944751"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 12 2b 23 11 11 11 12 9a 13 13 00 11 13 28 ?? ?? ?? 0a 13 14 11 14 2c 07 00 07 17 58 0b 2b 0f 00 11 12 17 58 13 12 11 12 11 11 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AHAB_2147947125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AHAB!MTB"
        threat_id = "2147947125"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {ff ff 11 08 74 ?? 00 00 01 75 ?? 00 00 01 74 ?? 00 00 1b 11 09 11 07 11 0a 25 17 58 13 0a 91 08 61 d2 9c 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Quasar_AQR_2147947342_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Quasar.AQR!MTB"
        threat_id = "2147947342"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 8e 69 8d 12 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

