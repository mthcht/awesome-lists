rule Trojan_MSIL_StormKitty_NEA_2147829227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.NEA!MTB"
        threat_id = "2147829227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {60 13 07 08 11 06 11 07 1f 18 5b d2 8c 26 00 00 01 6f 0e 01 00 0a 11 07 1f 18 5d 13 05 07 11 04 06 11 05 93 9d 11 06 17 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_NE_2147829565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.NE!MTB"
        threat_id = "2147829565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Landskip Yard Care" ascii //weight: 1
        $x_4_2 = "F569C6ED0B2B1741A14E2E9CC" ascii //weight: 4
        $x_4_3 = "KDikMXewCI" ascii //weight: 4
        $x_1_4 = "Card Puncher" ascii //weight: 1
        $x_1_5 = "b77a5c561934e089" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_RD_2147831858_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.RD!MTB"
        threat_id = "2147831858"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "//195.178.120.230/file/" wide //weight: 1
        $x_1_2 = {07 20 80 00 00 00 2b 49 28 15 00 00 0a 72 ?? ?? ?? ?? 6f 16 00 00 0a 7e 01 00 00 04 20 e8 03 00 00 73 17 00 00 0a 0c 07 08 07 6f 18 00 00 0a 1e 5b 6f 19 00 00 0a 6f 1a 00 00 0a 07 08 07 6f 1b 00 00 0a 1e 5b 6f 19 00 00 0a 6f 1c 00 00 0a 2b 07 6f 1d 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_ABAU_2147833562_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.ABAU!MTB"
        threat_id = "2147833562"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 16 1f 1a 6f ?? ?? ?? 0a 0b 07 1f 41 58 28 ?? ?? ?? 0a 0d 08 12 03 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 00 11 04 17 58 13 04 11 04 02 fe 04 13 05 11 05 2d cb}  //weight: 1, accuracy: Low
        $x_1_2 = "GetAntivirus" ascii //weight: 1
        $x_1_3 = "WindowsCare.YanBotnetHelper.Utility" ascii //weight: 1
        $x_1_4 = "$6cc69e93-1a70-48e9-8db8-9cddcdcf0238" ascii //weight: 1
        $x_1_5 = "Yan Botnet Demo 1 || Yan Tech" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_ABCC_2147834856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.ABCC!MTB"
        threat_id = "2147834856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateInstance" ascii //weight: 1
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "GetManifestResourceStream" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_3_5 = "V2luZG93cyBEZWZlbmRlciBTZWN1cml0eSQ=" wide //weight: 3
        $x_3_6 = "Windows Defender Security&" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_NEAA_2147838392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.NEAA!MTB"
        threat_id = "2147838392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {fe 1c 28 00 00 01 58 00 28 3e 01 00 0a 0a 06 72 ?? 20 00 70 6f 3f 01 00 0a 72 ?? 21 00 70 6f ea 00 00 0a 0b 07 3a 06 00 00 00 72 ?? 21 00 70 2a}  //weight: 10, accuracy: Low
        $x_2_2 = "DigitalProductId" wide //weight: 2
        $x_2_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion" wide //weight: 2
        $x_2_4 = "discordcanary" wide //weight: 2
        $x_2_5 = ".minecraft\\launcher_profiles.json" wide //weight: 2
        $x_2_6 = "netsh wlan show profile" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_MBT_2147838480_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.MBT!MTB"
        threat_id = "2147838480"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 06}  //weight: 1, accuracy: Low
        $x_1_2 = "AfzdIHOfGi7323Sf" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_NEAC_2147838962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.NEAC!MTB"
        threat_id = "2147838962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {58 9e 09 11 04 11 09 d2 9c 09 11 04 17 58 11 09 1e 64 d2 9c 09 11 04 18 58 11 09 1f 10 64 d2 9c 09 11 04 19 58 11 09 1f 18 64 d2 9c 11 04 1a 58 13 04 11 08 17 58 13 08 11 08 02 8e 69 32 9e}  //weight: 10, accuracy: High
        $x_5_2 = "dfgrusedjky.exe" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_NEAD_2147841310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.NEAD!MTB"
        threat_id = "2147841310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "66ba8ce2-518c-4734-8687-acc26ac403e9" ascii //weight: 5
        $x_2_2 = "gilrfdir5l7gse.exe" ascii //weight: 2
        $x_2_3 = "Confuser.Core 1.6.0+447341964f" ascii //weight: 2
        $x_2_4 = "Decrypt" ascii //weight: 2
        $x_2_5 = "GetExecutingAssembly" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_MBCD_2147846041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.MBCD!MTB"
        threat_id = "2147846041"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 16 0c 2b 20 08 02 07 02 8e 69 5d 91 58 06 07 91 58 20 ff 00 00 00 5f 0c 06 07 08 28 09 00 00 06 07 17 58 0b 07 20 00 01 00 00 32 d8}  //weight: 1, accuracy: High
        $x_1_2 = {57 15 02 08 09 0a 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 0d 00 00 00 04 00 00 00 04 00 00 00 0c 00 00 00 11 00 00 00 14 00 00 00 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_MBDC_2147847141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.MBDC!MTB"
        threat_id = "2147847141"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 11 04 6f ?? 01 00 0a 13 06 08 12 06 28 ?? 01 00 0a 6f ?? 01 00 0a 00 11 04 17 58 13 04 00 11 04 07 6f ?? 01 00 0a 13 08 12 08 28 ?? 01 00 0a fe 04 13 07 11 07 2d c6}  //weight: 1, accuracy: Low
        $x_1_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 00 1d 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 00 03 4c 00 00 03 6f 00 00 05 61 00 64 00 00 0b 53 00 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_ASK_2147891445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.ASK!MTB"
        threat_id = "2147891445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 25 17 03 a2 25 18 72 2f 09 00 70 a2 25 19 04 a2 25 1a 72 5b 09 00 70 a2 25 1b 02 a2 25 1c 72 69 09 00 70 a2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_AST_2147891496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.AST!MTB"
        threat_id = "2147891496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 03 1e 8d ?? 00 00 01 17 73 ?? 00 00 0a 0b 73 ?? 00 00 0a 25 07 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 00 25 07 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 00 0c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_AAUE_2147894285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.AAUE!MTB"
        threat_id = "2147894285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 11 0f 02 11 0f 91 11 07 61 11 0a 11 08 91 61 b4 9c 11 08 03 6f ?? 00 00 0a 17 da 33 05 16 13 08 2b 06 11 08 17 d6 13 08 11 0f 17 d6 13 0f 11 0f 11 10 31 ca}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_AAXB_2147897032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.AAXB!MTB"
        threat_id = "2147897032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 12 00 28 ?? 00 00 06 06 74 ?? 00 00 01 0a 12 00 28 ?? 00 00 06 06 74 ?? 00 00 01 0a 12 00 28 ?? 00 00 06 06 74 ?? 00 00 01 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_KAA_2147905231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.KAA!MTB"
        threat_id = "2147905231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 5d 91 61 20 00 01 00 00 58 06 08 06 8e 69 5d 91 59 20 00 01 00 00 5d d2 9c 00 08 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_MBWH_2147928625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.MBWH!MTB"
        threat_id = "2147928625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 60 0c 03 19 8d ?? 00 00 01 25 16 12 ?? 28 ?? 00 00 0a 9c 25 17 12 ?? 28 ?? 00 00 0a 9c 25 18}  //weight: 2, accuracy: Low
        $x_1_2 = {4c 00 6f 00 61 00 64}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_SWA_2147935624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.SWA!MTB"
        threat_id = "2147935624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 20 00 01 00 00 6f ?? 00 00 0a 09 20 80 00 00 00 6f ?? 00 00 0a 7e 04 00 00 04 7e 03 00 00 04 20 e8 03 00 00 73 47 00 00 0a 13 04 09 11 04 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 11 04 09 6f ?? 00 00 0a 1e 5b 6f ?? 00 00 0a 6f ?? 00 00 0a 09 17 6f ?? 00 00 0a 08 09 6f ?? 00 00 0a 17 73 4f 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_EAPQ_2147937893_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.EAPQ!MTB"
        threat_id = "2147937893"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 11 04 06 11 04 8f 12 00 00 01 72 37 49 00 70 28 61 01 00 0a a2 11 04 17 58 13 04 11 04 6a 07 6e 32 dd}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_StormKitty_MKV_2147941624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/StormKitty.MKV!MTB"
        threat_id = "2147941624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "StormKitty"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {32 e6 02 06 28 ?? 01 00 0a 0b 07 7e b0 02 00 04 32 02 14 2a 06 1a 58 0a 07 8d ac 00 00 01 0c 02 06 08 16 07 28 ?? 01 00 0a 06 07 58 0a 02 06 28 ?? 01 00 0a 0d 09 7e b0 02 00 04 32 02 14 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

