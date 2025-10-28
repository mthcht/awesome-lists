rule Trojan_MSIL_Razy_B_2147727821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.B"
        threat_id = "2147727821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {73 3c 00 00 0a 0a 02 16 28 45 00 00 0a 0b 06 02 1a 02 8e 69 1a 59 6f 3e 00 00 0a 07 8d 0c 00 00 01 0c 06 16 6a 6f 40 00 00 0a 06 16 73 46 00 00 0a 0d 09 08 16 08 8e 69 6f 42 00 00 0a 26 08 2a}  //weight: 1, accuracy: High
        $x_1_2 = {02 7b 09 00 00 04 61 20 20 a7 00 00 58 d1 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_DHA_2147757265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.DHA!MTB"
        threat_id = "2147757265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "uiyaehfiuwanf" ascii //weight: 1
        $x_1_2 = "sdfjhaihwu4h9" ascii //weight: 1
        $x_1_3 = "90sjfioajw4w9o" ascii //weight: 1
        $x_1_4 = "ushfga89hf8w9e" ascii //weight: 1
        $x_1_5 = "suyh387rqh9IASHJ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_Razy_DHB_2147758146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.DHB!MTB"
        threat_id = "2147758146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "kjvshka.*kjvshka" ascii //weight: 1
        $x_1_2 = "hseflkjsenf" ascii //weight: 1
        $x_1_3 = "skjvnlskdjnc" ascii //weight: 1
        $x_1_4 = "aildkjchblakjsc" ascii //weight: 1
        $x_1_5 = "lqakdjchblaskjdcn" ascii //weight: 1
        $x_1_6 = "eufgyhsouyeht83" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Razy_DLKT_2147786566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.DLKT!MTB"
        threat_id = "2147786566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Yoink Support Bot" wide //weight: 1
        $x_1_2 = "Immortal Donkey" wide //weight: 1
        $x_1_3 = "1F1tAaz5x1HUXrCNLbtMDqcw6o5GNn4xqX" wide //weight: 1
        $x_1_4 = "Properties/Injecting.txt" wide //weight: 1
        $x_1_5 = "EasyExploits DLL" wide //weight: 1
        $x_1_6 = "RobloxPlayerLauncher.exe" wide //weight: 1
        $x_1_7 = "http://api.thundermods.com/dlldownload.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_PSHE_2147841341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.PSHE!MTB"
        threat_id = "2147841341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 22 00 00 04 72 33 05 00 70 28 23 00 00 0a 28 29 00 00 0a 0a 02 7b 22 00 00 04 72 33 05 00 70 28 23 00 00 0a 28 84 00 00 0a 02 7b 22 00 00 04 72 33 05 00 70 28 23 00 00 0a 18 18 73 30 00 00 0a 0b 06 73 7e 00 00 0a 0c 08 6f 7f 00 00 0a 08 6f 80 00 00 0a 13 0b 2b 14 12 0b 28 81 00 00 0a 0d 07 09 66 1f 53 61 d2 6f 36 00 00 0a 12 0b 28 82 00 00 0a 2d e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_AR_2147846438_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.AR!MTB"
        threat_id = "2147846438"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 05 9a 0c 28 53 00 00 0a 08 6f 55 00 00 0a 0d 08 72 f7 00 00 70 6f 56 00 00 0a 08 72 0b 01 00 70 6f 56 00 00 0a 60 2d 47 02 7b 0b 00 00 04 28 57 00 00 0a 08 28 58 00 00 0a 18 18 73 59 00 00 0a 13 04 09 11 04 6f 5a 00 00 0a de 0c 11 04 2c 07 11 04}  //weight: 2, accuracy: High
        $x_1_2 = "BlackBinderStub.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_CXRM_2147847750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.CXRM!MTB"
        threat_id = "2147847750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://soft.fileshipoo.com/ford/cache_update.php" wide //weight: 1
        $x_1_2 = "http://soft.fileshipoo.com/ford/submit_ticket.php" wide //weight: 1
        $x_1_3 = "SELECT * FROM AntivirusProduct" wide //weight: 1
        $x_1_4 = "SELECT Caption FROM Win32_OperatingSystem" wide //weight: 1
        $x_1_5 = "mjkZXq6mWqyd1fBtT1u" ascii //weight: 1
        $x_1_6 = "zBd18G6G3bQKZjaeIMj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_NRZ_2147848733_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.NRZ!MTB"
        threat_id = "2147848733"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 08 28 1e 00 00 0a 0a 1f 1a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0b 07 06 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 07 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "BcmcnB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_ARA_2147848813_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.ARA!MTB"
        threat_id = "2147848813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0c 2b 10 11 04 07 08 9a 6f ?? ?? ?? 0a 13 04 08 17 ?? 0c 08 11 05 31 eb 11 04 07 08 9a}  //weight: 2, accuracy: Low
        $x_1_2 = "Lanzador" wide //weight: 1
        $x_1_3 = "Paila" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_ARA_2147848813_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.ARA!MTB"
        threat_id = "2147848813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {18 18 73 23 00 00 0a 13 04 09 11 04 6f ?? ?? ?? 0a de 0c 11 04 2c 07 11 04 6f ?? ?? ?? 0a dc 02 7b 0b 00 00 04 28}  //weight: 2, accuracy: Low
        $x_1_2 = "BlackBinderStub.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_ARA_2147848813_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.ARA!MTB"
        threat_id = "2147848813"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 05 2b 3c 12 05 28 70 00 00 0a 0b 00 07 28 2a 00 00 06 16 fe 01 13 04 11 04 2d 04 07 0d de 47 07 28 2b 00 00 06 0c 08 7e 5a 00 00 0a 28 71 00 00 0a 16 fe 01 13 04 11 04 2d 04}  //weight: 1, accuracy: High
        $x_1_2 = {13 04 2b 2b 12 04 28 70 00 00 0a 0b 00 07 28 29 00 00 06 0c 08 28 73 00 00 0a 0d 09 2d 08 03 08 6f 74 00 00 0a 00 07 03 28 2c 00 00 06 00 00 12 04 28 72 00 00 0a 0d 09 2d ca}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_PSSJ_2147851037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.PSSJ!MTB"
        threat_id = "2147851037"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {99 07 17 99 28 ?? 00 00 06 58 6f ?? 00 00 0a 00 09 28 ?? 00 00 2b 13 04 09 28 ?? 00 00 2b 08 fe 02 13 0b 11 0b 2c 1c 00 09 28 ?? 00 00 2b 13 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_KA_2147890153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.KA!MTB"
        threat_id = "2147890153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {17 59 0d 38 ?? 00 00 00 07 09 6f ?? 00 00 0a 74 ?? 00 00 1b 13 04 02 11 04 16 94 91 13 05 02 11 04 16 94 02 11 04 17 94 91 9c 02 11 04 17 94 11 05 9c 09 17 59 0d 09 16}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_KAB_2147895795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.KAB!MTB"
        threat_id = "2147895795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 84 30 5f 30 34 00 84 30 5f 30 34 00 84 30 5f 30 34 00 84 30 5f 30 34 00 84 30 5f 30 34 00 84}  //weight: 1, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_KAC_2147896421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.KAC!MTB"
        threat_id = "2147896421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 65 5f 91 04 60 61 d1 9d 06 20 ?? ?? ?? ?? 66 66 66 20 ?? ?? ?? ?? 61 66 20 ?? ?? ?? ?? 61 20 ?? ?? ?? ?? 61 66 20 ?? ?? ?? ?? 61 66 59 25 0a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_PTEC_2147899088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.PTEC!MTB"
        threat_id = "2147899088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 28 54 00 00 06 0c 11 07 20 e5 e9 b2 53 5a 20 3a 73 10 52}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_AMBH_2147900301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.AMBH!MTB"
        threat_id = "2147900301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 0e 03 00 fe ?? ?? 00 00 01 58 00 59 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a fe 0c 01 00 20}  //weight: 2, accuracy: Low
        $x_2_2 = {fe 0c 01 00 fe 0c 02 00 93 fe 0e 03 00 fe 0c 00 00 fe 0c 03 00 fe 09 02 00 59 d1 6f ?? 00 00 0a 26 fe 0c 02 00 20 ?? 00 00 00 20 ?? ?? ?? ?? 65 65 65 65 65 65 65 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_NL_2147900615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.NL!MTB"
        threat_id = "2147900615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "soft.fileshipoo.com/ford/cache_update.php" ascii //weight: 5
        $x_1_2 = "SELECT * FROM AntivirusProduct" ascii //weight: 1
        $x_1_3 = "\\root\\SecurityCenter" ascii //weight: 1
        $x_1_4 = "/C schtasks /create /RU SYSTEM /sc minute /mo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_GPB_2147902605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.GPB!MTB"
        threat_id = "2147902605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {91 04 61 d2 9c 11 06 17 58 13}  //weight: 5, accuracy: High
        $x_5_2 = {00 53 74 72 52 65 76 65 72 73 65 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_SPYU_2147903566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.SPYU!MTB"
        threat_id = "2147903566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 02 16 02 8e 69 6f ?? ?? ?? 0a 00 11 04 6f ?? ?? ?? 0a 00 00 dd 17 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_PPD_2147925390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.PPD!MTB"
        threat_id = "2147925390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 63 00 00 0a 0a 06 72 0d 02 00 70 72 d9 01 00 70 28 ?? 00 00 06 72 b8 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_ZGM_2147954321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.ZGM!MTB"
        threat_id = "2147954321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 0a 2b 0e 03 06 03 06 91 1f 1e 61 d2 9c 06 17 58 0a 06 03 8e 69 32 ec 03 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_BAA_2147955940_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.BAA!MTB"
        threat_id = "2147955940"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 08 8f 08 00 00 01 25 71 08 00 00 01 20 aa 00 00 00 61 d2 81 08 00 00 01 08 17 58 0c 08 06 8e 69 32 dd}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "GetTempFileName" ascii //weight: 1
        $x_1_4 = "WriteAllBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Razy_PGRZ_2147956170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Razy.PGRZ!MTB"
        threat_id = "2147956170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Razy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 16 0c 2b 1d 06 08 8f ?? 00 00 01 25 71 ?? 00 00 01 20 ?? 00 00 00 61 d2 81 ?? 00 00 01 08 17 58 0c 08 06 8e 69 32 dd}  //weight: 5, accuracy: Low
        $x_5_2 = {43 00 3a 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 4d 00 65 00 64 00 69 00 61 00 5c 00 [0-15] 2e 00 65 00 78 00 65 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

