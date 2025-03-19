rule Trojan_MSIL_Discord_MB_2147810502_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discord.MB!MTB"
        threat_id = "2147810502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fa 01 33 00 16 ?? ?? 01 ?? ?? ?? 36 ?? ?? ?? 05 ?? ?? ?? 0a ?? ?? ?? 0f ?? ?? ?? 07 ?? ?? ?? 4e ?? ?? ?? 13}  //weight: 10, accuracy: Low
        $x_3_2 = "HttpClient" ascii //weight: 3
        $x_3_3 = "SecurityProtocolType" ascii //weight: 3
        $x_3_4 = "System.Net" ascii //weight: 3
        $x_3_5 = "set_SecurityProtocol" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Discord_MB_2147810502_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discord.MB!MTB"
        threat_id = "2147810502"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 1f 20 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0b 06 1f 20 28 ?? ?? ?? 2b 1f 20 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0c 06 1f 40 28 ?? ?? ?? 2b 06 8e 69 1f 40 59 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0d 03 07 20 e8 03 00 00 73 ?? ?? ?? 0a 13 04}  //weight: 1, accuracy: Low
        $x_1_2 = "YNvC57lW1z8ea1CSB" wide //weight: 1
        $x_1_3 = "Decrypt" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "RijndaelManaged" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "GetBytes" ascii //weight: 1
        $x_1_8 = "sendDiscordWebhook" ascii //weight: 1
        $x_1_9 = "MemoryStream" ascii //weight: 1
        $x_1_10 = "Sleep" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Discord_MC_2147813791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discord.MC!MTB"
        threat_id = "2147813791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Border_MouseDown" ascii //weight: 1
        $x_1_2 = "encrypt_MouseDown" ascii //weight: 1
        $x_1_3 = "FurkByteCode.dll" wide //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "MemoryStream" ascii //weight: 1
        $x_1_8 = "pLv8pJsxuO" ascii //weight: 1
        $x_1_9 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Discord_M_2147821696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discord.M!MTB"
        threat_id = "2147821696"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ZuMiner.pdb" ascii //weight: 1
        $x_1_2 = "RandomWallet" ascii //weight: 1
        $x_1_3 = "Exodus\\exodus.wallet" wide //weight: 1
        $x_1_4 = "Discord\\Tokens.txt" wide //weight: 1
        $x_1_5 = "wallet.id.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Discord_N_2147821697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discord.N!MTB"
        threat_id = "2147821697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Users\\Lisa\\AppData\\Roaming\\Lime" wide //weight: 1
        $x_1_2 = "Windows Security Health Serviceexe" wide //weight: 1
        $x_1_3 = "System.Web.Services.Protocols.SoapHttpClientProtocol" ascii //weight: 1
        $x_1_4 = "ThreadSafeObjectProvider" ascii //weight: 1
        $x_1_5 = "MyWebServicesObjectProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Discord_ABG_2147824765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discord.ABG!MTB"
        threat_id = "2147824765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0a 05 2d 08 06 7e 63 ?? ?? 04 60 0a 05 6e 20 00 ?? ?? 80 6e 5f 2c 08 06 7e 64 ?? ?? 04 60 0a 02 04 61 03 04 61 5f 6e 20 00 ?? ?? 80 6e 5f 2c 08}  //weight: 2, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "CreateDelegate" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "get_CurrentDomain" ascii //weight: 1
        $x_1_7 = "RegistryKey" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Discord_ARA_2147847796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discord.ARA!MTB"
        threat_id = "2147847796"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 07 02 8e b7 5d 02 07 02 8e b7 5d 91 03 07 03 8e b7 5d 91 61 02 07 17 d6 02 8e b7 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 07 15 d6 0b 07 16 2f cb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Discord_GUF_2147896108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discord.GUF!MTB"
        threat_id = "2147896108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "thetastlr-default-rtdb.firebaseio.com" ascii //weight: 1
        $x_1_2 = "al1hiKheger50NenhKPzYiygGZGlsjmHMCwRYelt" ascii //weight: 1
        $x_1_3 = "checkip.dyndns.org" ascii //weight: 1
        $x_1_4 = "thetastealer" ascii //weight: 1
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "\\Release\\thetastealer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Discord_ARAZ_2147936375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Discord.ARAZ!MTB"
        threat_id = "2147936375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Discord"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 06 91 13 07 09 11 07 61 0d 11 06 17 58 13 06 11 06 11 05 8e 69 32 e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

