rule Trojan_MSIL_Snakekeylogger_PFH_2147819216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.PFH!MTB"
        threat_id = "2147819216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 06 00 fe 0c 0f 00 fe 0c 06 00 fe 0c 0f 00 91 fe 0c 0f 00 61 d2 9c 00 fe 0c 0f 00 20 01 00 00 00 58 fe 0e 0f 00 fe 0c 0f 00 fe 0c 06 00 8e 69 fe 04 fe 0e 10 00 fe 0c 10 00 3a bf ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_WRL_2147822406_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.WRL!MTB"
        threat_id = "2147822406"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 25 17 59}  //weight: 1, accuracy: High
        $x_1_2 = {fe 02 0c 08 2d df 28 ?? ?? ?? 06 00 16 2d e8 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_ZBM_2147822407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.ZBM!MTB"
        threat_id = "2147822407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0d 16 13 04 09 12 04 28 ?? ?? ?? 0a 07 08 02 08 91 6f ?? ?? ?? 0a de 0b 11 04 2c 06 09 28 ?? ?? ?? 0a dc 08 25 17 59 0c 16 fe 02 2d d2 07 6f ?? ?? ?? 0a 28 ?? ?? ?? 2b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_INFA_2147823557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.INFA!MTB"
        threat_id = "2147823557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 01 00 00 6f ?? ?? ?? 0a 09 08 6f ?? ?? ?? 0a 09 18 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 13 04 11 04 28 ?? ?? ?? 06 74 31 00 00 01 6f ?? ?? ?? 0a 17 9a 80 5b 00 00 04 23 66 66 66 66 66 66 28 40}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_OLM_2147825959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.OLM!MTB"
        threat_id = "2147825959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "subqtaneousshop.com/DK08748900098765000_Apiplndv.png" wide //weight: 2
        $x_2_2 = "subqtaneousshop.com/SKYTR0098734567890000_Lvhidmyy.bmp" wide //weight: 2
        $x_2_3 = "198.46.132.178/8888_Wyxyqhfl.bmp" wide //weight: 2
        $x_2_4 = "transfer.sh/get/eHbwxw/Lfqrohiar_Jngdbnwn.png" wide //weight: 2
        $x_2_5 = "toraech.com/Egmym_Nxdrvtat.jpg" wide //weight: 2
        $x_1_6 = "GetType" ascii //weight: 1
        $x_1_7 = "WebClient" ascii //weight: 1
        $x_1_8 = "DownloadData" ascii //weight: 1
        $x_1_9 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Snakekeylogger_DRFA_2147826271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.DRFA!MTB"
        threat_id = "2147826271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 03 00 00 04 73 6a 00 00 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 74 08 00 00 1b 0a 06 72 ?? ?? ?? 70 28 ?? ?? ?? 06 0b 07 72 ?? ?? ?? 70 28 ?? ?? ?? 06 74 46 00 00 01 6f ?? ?? ?? 0a 1a 9a 80 02 00 00 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_UAGA_2147829146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.UAGA!MTB"
        threat_id = "2147829146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 11 05 6e 11 08 6a 59 d4 11 04 1e 11 08 59 1e 5a 1f 3f 5f 64 20 ff 00 00 00 6a 5f d2 9c 11 08 17 59 13 08 11 08 16 3d d4 ff ff ff}  //weight: 1, accuracy: High
        $x_1_2 = "Kinomaniak Library" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_OOYF_2147829161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.OOYF!MTB"
        threat_id = "2147829161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 09 08 6f ?? ?? ?? 0a 09 18 6f ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a}  //weight: 1, accuracy: Low
        $x_1_2 = "Kinomaniak Library" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_UYFA_2147829224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.UYFA!MTB"
        threat_id = "2147829224"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 57 b7 a2 3f 09 0f 00 00 00 00 00 00 00 00 00 00 01 00 00 00 ?? 00 00 00 3d 00 00 00 ba}  //weight: 1, accuracy: Low
        $x_1_2 = "System.Security.Cryptography.AesCryptoServiceProvider" wide //weight: 1
        $x_1_3 = "11111-22222-10009-11112" wide //weight: 1
        $x_1_4 = "Reverse" ascii //weight: 1
        $x_1_5 = "CreateEncryptor" ascii //weight: 1
        $x_1_6 = "ToBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_IEGA_2147829994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.IEGA!MTB"
        threat_id = "2147829994"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 13 04 00 70 6f ?? ?? ?? 0a 1e 8d 63 00 00 01 17 73 78 00 00 0a 0b 73 79 00 00 0a 0c 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 07 1f 10 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 06 16 06 8e 69 6f ?? ?? ?? 0a 0d 09 8e 69 1f 10 59}  //weight: 2, accuracy: Low
        $x_1_2 = "585G54S4C5HBC5SYD54542" wide //weight: 1
        $x_1_3 = "SnakeI" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_AGEF_2147833824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.AGEF!MTB"
        threat_id = "2147833824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe 06 2b 00 00 06 73 34 00 00 0a 6f ?? ?? ?? 0a 00 73 09 00 00 06 0b 14 0c 08 14 fe 03 0d 09 2c 16 00 06 08}  //weight: 2, accuracy: Low
        $x_1_2 = "Helper_Classes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_AFSQ_2147837447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.AFSQ!MTB"
        threat_id = "2147837447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 02 00 00 04 06 6f ?? ?? ?? 0a 00 00 02 7b 04 00 00 04 6f ?? ?? ?? 0a 25 0a 14 fe 03 0c 08}  //weight: 2, accuracy: Low
        $x_1_2 = "Helper_Classes" wide //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "TransformFinalBlock" ascii //weight: 1
        $x_1_5 = "RC2CryptoServiceProvider" ascii //weight: 1
        $x_1_6 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_7 = "background_map_east1_start_1.png" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_ASK_2147842158_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.ASK!MTB"
        threat_id = "2147842158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 07 2b 1c 00 07 11 07 7e 04 00 00 04 11 07 91 08 11 07 09 5d 91 61 d2 9c 00 11 07 17 58 13 07 11 07 06 fe 04 13 08 11 08 2d d9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_ASK_2147842158_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.ASK!MTB"
        threat_id = "2147842158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 16 13 04 2b 32 09 08 17 8d 19 00 00 01 25 16 11 04 8c 5d 00 00 01 a2 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 86 6f ?? ?? ?? 0a 00 11 04 17 d6 13 04}  //weight: 2, accuracy: Low
        $x_1_2 = "Basic.Constants" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_ASK_2147842158_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.ASK!MTB"
        threat_id = "2147842158"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 00 7e 01 00 00 04 6f ?? 00 00 0a 05 16 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00}  //weight: 2, accuracy: Low
        $x_2_2 = {7e 02 00 00 04 28 ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 7e 01 00 00 04 06 6f ?? 00 00 0a 00 7e 01 00 00 04 18 6f}  //weight: 2, accuracy: Low
        $x_1_3 = "FrogcoinWallet" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_PSNT_2147847442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.PSNT!MTB"
        threat_id = "2147847442"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 40 0a 00 70 06 72 4c 0a 00 70 6f ?? ?? ?? 0a 72 56 0a 00 70 72 5a 0a 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 0c 16 0d 2b 20 00 07 09 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 13 05 08 11 05 6f ?? ?? ?? 0a 00 09 18 58 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_PSXW_2147891499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.PSXW!MTB"
        threat_id = "2147891499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 3b 00 00 0a 28 ?? 00 00 2b 0b 72 1a 03 00 70 28 ?? 00 00 06 02 7b 09 00 00 04 02 07 28 ?? 00 00 06 28 ?? 00 00 0a 0c 08 28 ?? 00 00 0a 72 e0 01 00 70 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_GTR_2147895974_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.GTR!MTB"
        threat_id = "2147895974"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 46 63 2b 97 28 ?? ?? ?? 06 07 08 28 ?? ?? ?? 06 0b 08 15 58 0c 08 16 fe 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_ANS_2147896122_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.ANS!MTB"
        threat_id = "2147896122"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 2b 14 07 06 07 8e 69 5d 02 06 08 07 28 ?? ?? ?? 06 9c 06 15 58 0a 06 16 fe 04 16 fe 01 13 05 11 05 2d df}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_ASN_2147896125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.ASN!MTB"
        threat_id = "2147896125"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 4d 02 00 70 28 80 00 00 06 15 2d 22 26 28 98 00 00 0a 06 6f 99 00 00 0a 28 9a 00 00 0a 1c 2d 11 26 02 07 28 7f 00 00 06 18 2d 09 26 de 0c 0a 2b dc 0b 2b ed 0c 2b f5 26 de c3}  //weight: 1, accuracy: High
        $x_1_2 = {16 1d 2d 0c 26 03 8e 69 17 59 1b 2d 06 26 2b 24 0a 2b f2 0b 2b f8 03 06 91 1e 2d 15 26 03 06 03 07 91 9c 03 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_SCXF_2147924286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.SCXF!MTB"
        threat_id = "2147924286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 dd 2f 00 00 00 11 04}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_SVZA_2147926661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.SVZA!MTB"
        threat_id = "2147926661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0e 05 1f 7b 61 20 ff 00 00 00 5f 0a 06 20 ?? 01 00 00 58 20 00 01 00 00 5e 0a 06 16 fe 01 0b 07 2c 02 17 0a 05 03 04 03 91 0e 04 0e 05 95 61 d2 9c}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_SFRA_2147927070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.SFRA!MTB"
        threat_id = "2147927070"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 d1 13 15 11 1f 11 09 91 13 25 11 1f 11 09 11 25 11 27 61 11 1d 19 58 61 11 33 61 d2 9c}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_SHCK_2147928520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.SHCK!MTB"
        threat_id = "2147928520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {0d 03 19 8d 4e 00 00 01 25 16 11 09 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 09 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 09 20 ff 00 00 00 5f d2 9c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_SKPK_2147928805_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.SKPK!MTB"
        threat_id = "2147928805"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 04 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 0a dd 0f 00 00 00 11 04 39 07 00 00 00 11 04 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_SUPD_2147930693_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.SUPD!MTB"
        threat_id = "2147930693"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {19 00 03 06 7e ?? 00 00 04 06 91 02 06 02 8e 69 5d 91 61 d2 9c 00 06 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_PHP_2147934303_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.PHP!MTB"
        threat_id = "2147934303"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 2c 4f 00 0f 00 28 ?? 01 00 0a 0f 00 28 ?? 01 00 0a 61 0f 00 28 ?? 01 00 0a 61 d2 0d 09 28 ?? 00 00 06 00 04 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 01 00 0a 9c 25 17 0f 00 28 ?? 01 00 0a 9c 25 18 0f 00 28 ?? 01 00 0a 9c 6f ?? 01 00 0a 00 00 2b 15}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakekeylogger_SHLH_2147935884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakekeylogger.SHLH!MTB"
        threat_id = "2147935884"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakekeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 16 02 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 02 1e 63 20 ff 00 00 00 5f d2 9c 25 18 02 20 ff 00 00 00 5f d2 9c 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

