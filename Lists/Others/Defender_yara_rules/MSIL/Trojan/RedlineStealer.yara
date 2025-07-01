rule Trojan_MSIL_RedlineStealer_GR_2147815756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.GR!MTB"
        threat_id = "2147815756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "tiny.one/cya7dmsu" ascii //weight: 1
        $x_1_2 = "PortableApps.com" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "InvokeMember" ascii //weight: 1
        $x_1_6 = "Ebuzczkipwbedwf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_RPJ_2147819207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.RPJ!MTB"
        threat_id = "2147819207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 2d 00 00 0a 0a 12 00 23 00 00 00 00 00 00 24 40 28 2e 00 00 0a 0b 2b 23 08 2d 20 20 00 00 00 00 7e 41 00 00 04 7b 2c 00 00 04 2d 2f 45 02 00 00 00 23 00 00 00 df ff ff ff 2b 21 07 28 2d 00 00 0a 28 2f 00 00 0a 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_RPJ_2147819207_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.RPJ!MTB"
        threat_id = "2147819207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "M03illa" ascii //weight: 1
        $x_1_2 = "Discord" ascii //weight: 1
        $x_1_3 = "DownloadUpdate" ascii //weight: 1
        $x_1_4 = "CommandLineUpdate" ascii //weight: 1
        $x_1_5 = "DownloadAndExecuteUpdate" ascii //weight: 1
        $x_1_6 = "NordApp" ascii //weight: 1
        $x_1_7 = "AllWallets" ascii //weight: 1
        $x_1_8 = "CryptoHelper" ascii //weight: 1
        $x_1_9 = "UpdateShortRep" ascii //weight: 1
        $x_1_10 = "ReverseDecode" ascii //weight: 1
        $x_1_11 = "Invoke" ascii //weight: 1
        $x_1_12 = "LoadModule" ascii //weight: 1
        $x_1_13 = "Reverse" ascii //weight: 1
        $x_1_14 = "ReadByte" ascii //weight: 1
        $x_1_15 = "ToBase64String" ascii //weight: 1
        $x_1_16 = "Encoding" ascii //weight: 1
        $x_1_17 = "CopyBlock" ascii //weight: 1
        $x_1_18 = "MemoryStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_MBAL_2147840181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.MBAL!MTB"
        threat_id = "2147840181"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 0a 00 00 0a 03 50 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 08 18 6f ?? 00 00 0a 08 6f 10 00 00 0a 02 50 16 02 50 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = "xDTTHrgPLZZzGqKBFfoSK" ascii //weight: 1
        $x_1_3 = "IMvxProducer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_PSJB_2147844778_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.PSJB!MTB"
        threat_id = "2147844778"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 22 26 00 06 0b 07 1f 20 8d 25 00 00 01 25 d0 36 14 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 1f 10 8d 25 00 00 01 25 d0 37 14 00 04 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 07 6f ?? ?? ?? 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ce 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_PSAO_2147899286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.PSAO!MTB"
        threat_id = "2147899286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 55 a2 0b 09 0f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 68 00 00 00 70 07 00 00 7a 00 00 00 87 3a 00 00 91 00}  //weight: 5, accuracy: High
        $x_1_2 = "nOpCoOpCoOpCoO0Co" ascii //weight: 1
        $x_1_3 = "5nOpcoOp;nOpAoOpCoOpCoOpCoOPCo/" ascii //weight: 1
        $x_1_4 = "CROWCoOpCoO" ascii //weight: 1
        $x_1_5 = "Y@(K5" ascii //weight: 1
        $x_1_6 = "@~@(w" ascii //weight: 1
        $x_1_7 = "System.Security.Cryptography.HMACMD5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_PSBI_2147899324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.PSBI!MTB"
        threat_id = "2147899324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 06 16 2e 16 12 00 12 01 12 02 7e 06 00 00 04 06 97 29 1a 00 00 11 0d 00 2b e5}  //weight: 5, accuracy: High
        $x_2_2 = "bhaupadvfvxVtouojoaupadvfvxVtouojoaupadvfvxUDfuxjoaupadaKsd{}D{Ghoas[" ascii //weight: 2
        $x_2_3 = "uozoaupqdvvvxVtou" ascii //weight: 2
        $x_2_4 = "joaupadvfvx" ascii //weight: 2
        $x_2_5 = "kdvdvxVtouojoaupadVfv" ascii //weight: 2
        $x_2_6 = "natpadvfvx" ascii //weight: 2
        $x_1_7 = "ICryptoTransformExecute" ascii //weight: 1
        $x_1_8 = "DebuggingModes" ascii //weight: 1
        $x_1_9 = "DarkYellowToByteArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 4 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_RedlineStealer_RPY_2147900595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.RPY!MTB"
        threat_id = "2147900595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {71 1f 00 00 01 20 9a 00 00 00 61 d2 81 1f 00 00 01 02 50 06 8f 1f 00 00 01 25 71 1f 00 00 01 1f 40 58 d2 81 1f 00 00 01 02 50 06 8f 1f 00 00 01 25 71 1f 00 00 01 1f 43 59 d2 81 1f 00 00 01 02 50 06 8f 1f 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_RPY_2147900595_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.RPY!MTB"
        threat_id = "2147900595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "loginusers.vdf" wide //weight: 1
        $x_1_2 = "Tokens.txt" wide //weight: 1
        $x_1_3 = "Kazakhstan" wide //weight: 1
        $x_1_4 = "Russia" wide //weight: 1
        $x_1_5 = "shell\\open\\command" wide //weight: 1
        $x_1_6 = "api.ip.sb/ip" wide //weight: 1
        $x_1_7 = "AllWallets" ascii //weight: 1
        $x_1_8 = "WhoIsLocking" ascii //weight: 1
        $x_1_9 = "GetBrowsers" ascii //weight: 1
        $x_1_10 = "GetGraphicCards" ascii //weight: 1
        $x_1_11 = "QueryAV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_RPZ_2147900596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.RPZ!MTB"
        threat_id = "2147900596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 1d 00 00 01 02 50 06 8f 1d 00 00 01 25 71 1d 00 00 01 20 af 00 00 00 59 d2 81 1d 00 00 01 02 50 06 8f 1d 00 00 01 25 71 1d 00 00 01 20 e8 00 00 00 58 d2 81 1d 00 00 01 02 50 06 8f 1d 00 00 01 25 71 1d 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_RPX_2147902014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.RPX!MTB"
        threat_id = "2147902014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91 13 07 06 08 06 09 91 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_RPX_2147902014_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.RPX!MTB"
        threat_id = "2147902014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 20 06 00 00 00 38 f2 fb ff ff 16 13 04 20 05 00 00 00 fe 0e 03 00 38 dd fb ff ff 1f 0a 13 00 20 06 00 00 00 38 d3 fb ff ff 11 00 11 0a 3e 56 ff ff ff 20 0a 00 00 00 38 c0 fb ff ff 11 04 17 58 13 04 20 1e 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_NA_2147904133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.NA!MTB"
        threat_id = "2147904133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 08 91 0d 08 1f 09 5d ?? ?? 03 11 04 9a 13 05 02 08 11 05 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_NB_2147904513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.NB!MTB"
        threat_id = "2147904513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 07 17 ?? ?? 00 00 0a 11 06 91 1b 61 b4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_NC_2147905365_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.NC!MTB"
        threat_id = "2147905365"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {38 15 00 00 00 00 02 06 8f ?? 00 00 01 25 47 03 06 91 61 d2 52 00 06 17 59 0a 06 16 fe 04 16 fe 01 0b 07 3a dd ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_AMAA_2147909780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.AMAA!MTB"
        threat_id = "2147909780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 09 08 91 09 07 91 58 20 00 01 00 00 5d 13 ?? 03 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 09 11 ?? 91 61 d2 81 ?? 00 00 01 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_NE_2147916587_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.NE!MTB"
        threat_id = "2147916587"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {16 13 07 2b 0d 11 08 17 58 13 08 11 08 07 8e 69}  //weight: 3, accuracy: High
        $x_3_2 = {11 06 17 58 13 06 11 06 06 8e 69 07 8e 69 59}  //weight: 3, accuracy: High
        $x_4_3 = "9A0668AA-2E7F-4FFD-A690-21D53CF99999" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_KAM_2147919567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.KAM!MTB"
        threat_id = "2147919567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 08 02 04 08 1e 5d 9a 28 ?? 00 00 0a 03 08 91 28 ?? 00 00 06 28 ?? 00 00 0a 9c 08 17 d6 0c 08 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_AMAI_2147920021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.AMAI!MTB"
        threat_id = "2147920021"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 17 58 20 00 01 00 00 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 08 91}  //weight: 1, accuracy: High
        $x_2_2 = {6e 5b 26 02 11 ?? 8f ?? 00 00 01 25 71 ?? 00 00 01 06 11 ?? 91 61 d2 81 ?? 00 00 01 11 ?? 17 58 13 ?? 11 ?? 02 8e 69 3f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_AMH_2147922555_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.AMH!MTB"
        threat_id = "2147922555"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 5b 26 11 ?? 6e 11 ?? 6a 5b 26 11}  //weight: 1, accuracy: Low
        $x_4_2 = {0a 26 16 13 ?? 12 ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 13 ?? 03 11 ?? 91 13 ?? 06 11 ?? 91 13 ?? 11 ?? 11 ?? 61 d2 13}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_SZA_2147929054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.SZA!MTB"
        threat_id = "2147929054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 11 15 1f 1f 5f 8f 89 00 00 01 25 4a 11 12 11 15 1e 5a 1f 1f 5f 63 61 54 11 15 17 58 13 15 11 15 1a fe 04 13 16 11 16 2d d6}  //weight: 1, accuracy: High
        $x_1_2 = "Account_Panel.Properties.Resources" ascii //weight: 1
        $x_1_3 = "$3eb20253-9dc7-4119-9a16-5cb763e8e3e8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_SZA_2147929054_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.SZA!MTB"
        threat_id = "2147929054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$996a36e4-64c8-4c48-bc33-95d7dcbcd09e" ascii //weight: 1
        $x_1_2 = "JYM_Project.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = {00 11 04 11 14 8f 60 00 00 01 25 47 11 0e 11 14 1e 5a 1f 1f 5f 63 d2 61 d2 52 00 11 14 17 58 13 14 11 14 1a fe 04 13 15 11 15 2d d4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_EHIZ_2147945213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.EHIZ!MTB"
        threat_id = "2147945213"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 07 20 d2 04 00 00 5a 61 0a 06 07 ?? ?? ?? ?? ?? 5a ?? ?? ?? ?? ?? 5d 58 0a 06 17 62 06 1f 1f 63 60 0a 07 17 58 0b 07 1f 0a 32 d4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_RedlineStealer_ENWL_2147945217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/RedlineStealer.ENWL!MTB"
        threat_id = "2147945217"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "RedlineStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6c 5b 13 22 1f 50 13 53 ?? ?? ?? ?? ?? ?? ?? ?? 00 00 11 21 1f 64 5d 58 13 23 22 a0 1a cf 3f 11 21 6b 5a 13 24 11 55 1f 72 91 1f 56 58 13 53}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

