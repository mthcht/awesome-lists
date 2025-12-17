rule Trojan_MSIL_Androm_D_2147730346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.D!MTB"
        threat_id = "2147730346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://tempuri.org/DataSet" wide //weight: 1
        $x_1_2 = "XFJ1blBcUnVuUFxvYmpcRGVidWdcUnVuUC5wZGI" wide //weight: 1
        $x_1_3 = {06 07 06 07 91 02 07 1f 10 5d 91 61 28 65 00 00 0a 9c}  //weight: 1, accuracy: High
        $x_1_4 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_Androm_J_2147740583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.J!ibt"
        threat_id = "2147740583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 06 07 91 1f ?? 61 d2 9c}  //weight: 1, accuracy: Low
        $x_1_2 = {28 0f 00 00 0a 7e 01 00 00 04 6f 10 00 00 0a 0a}  //weight: 1, accuracy: High
        $x_1_3 = {02 74 16 00 00 01 6f 19 00 00 0a 14 16 8d 01 00 00 01 6f 1a 00 00 0a 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_A_2147743728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.A!MTB"
        threat_id = "2147743728"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 7e 01 00 00 04 8e 69 fe 04 2d 01 2a 06 0b 1f 0b 0c 07 08 5d 2c 03 16 2b 01 17 16 fe 03 2c 14 7e 01 00 00 04 06 7e 01 00 00 04 06 91 1d 59 1f 09 59 d2 9c 06 25 0b 0d 17 25 0c 13 04 11 04 2c d1 09 11 04 58 0a 2b b8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AS_2147786450_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AS!MTB"
        threat_id = "2147786450"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "DAL_Download_List_Generator" ascii //weight: 3
        $x_3_2 = "imimimimim" ascii //weight: 3
        $x_3_3 = "GetFileNameByURL" ascii //weight: 3
        $x_3_4 = "DebuggableAttribute" ascii //weight: 3
        $x_3_5 = "FGExecute" ascii //weight: 3
        $x_3_6 = "KillTask" ascii //weight: 3
        $x_3_7 = "quitClick" ascii //weight: 3
        $x_3_8 = "Activity_Logger" ascii //weight: 3
        $x_3_9 = "WorkerExecute" ascii //weight: 3
        $x_3_10 = "DropdownKill" ascii //weight: 3
        $x_3_11 = "set_UseShellExecute" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_DA_2147816358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.DA!MTB"
        threat_id = "2147816358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {01 57 17 a2 09 09 0b 00 00 00 5a a4 01 00 16 00 00 01 00 00 00 5e 00 00 00 1b 00 00 00 35 00 00 00 65}  //weight: 3, accuracy: High
        $x_3_2 = "HttpWebResponse" ascii //weight: 3
        $x_3_3 = "System.Security.Cryptography" ascii //weight: 3
        $x_3_4 = "TripleDES" wide //weight: 3
        $x_3_5 = "Rijndael" wide //weight: 3
        $x_3_6 = "CreateDecryptor" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_APZ_2147832708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.APZ!MTB"
        threat_id = "2147832708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 0b 00 00 04 07 9a 06 17 28 ?? ?? ?? 0a 2d 12 7e 0c 00 00 04 07 9a}  //weight: 2, accuracy: Low
        $x_1_2 = "iRemovalProWPF.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_MBI_2147838130_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.MBI!MTB"
        threat_id = "2147838130"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 63 d2 48 28 61 9d fe 0c 0a 00 20 03 00 00 00 20 60 d4 d4 43 20 09 d4 d4 43 61 9d fe 0c 0a 00 20 04 00 00 00 20 16 05 36 6b 20 7b 05 36 6b 61 9d fe 0c 0a 00 20 05 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "485e-bda9-9139d5da9381" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_RB_2147838509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.RB!MTB"
        threat_id = "2147838509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 07 9a 74 ?? ?? ?? ?? 72 ?? ?? ?? ?? 20 00 01 00 00 14 14 14 6f ?? ?? ?? 0a 26 de 03 26 de 00 07 17 58 0b 07 06 8e 69 32 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_MBAK_2147838632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.MBAK!MTB"
        threat_id = "2147838632"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "193.56.146.114" ascii //weight: 1
        $x_1_2 = "fadsghserfgaezrhbsedfgfs" ascii //weight: 1
        $x_1_3 = "xzcvbzxfrghzxcbzdfgsayzdgsdfgdsfg" ascii //weight: 1
        $x_1_4 = "DownloadData" ascii //weight: 1
        $x_1_5 = "ZipCosdaz.Propertie" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_CB_2147838794_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.CB!MTB"
        threat_id = "2147838794"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {13 04 08 13 05 11 04 13 06 11 06 14 fe 03 13 07 11 07 2c 0b 11 06 6f 38 00 00 06 0b 00 2b 04 00 14 0b 00 11 05 07}  //weight: 3, accuracy: High
        $x_1_2 = "Pontoon.Resources" ascii //weight: 1
        $x_1_3 = "AfficherIngredients" ascii //weight: 1
        $x_1_4 = "Pontoon.Pizza2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_CQ_2147841265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.CQ!MTB"
        threat_id = "2147841265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 f7 02 0f 70 28 3e 00 00 0a 11 05 28 3f 00 00 0a 13 0d 11 0d 28 40 00 00 0a 26 11 0d 07 7b 06 00 00 04 72 07 03 0f 70 28 41 00 00 0a 13 0e 11 0e 28 42 00 00 0a 2d 2d}  //weight: 1, accuracy: High
        $x_1_2 = {11 0e 28 43 00 00 0a 25 11 0b 16 11 0b 8e 69 6f 44 00 00 0a 6f 2c 00 00 0a 11 0e 14 1a 28 26 00 00 06 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_MBAS_2147841638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.MBAS!MTB"
        threat_id = "2147841638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 0d 07 03 6f ?? 00 00 0a 5d 13 04 03 11 04 6f ?? 00 00 0a 13 05 11 05 13 06 09 11 06 61 13 07 11 07 d1 13 08 06 11 08 6f ?? 00 00 0a 26 00 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 13 0a 11 0a 2d b5}  //weight: 1, accuracy: Low
        $x_1_2 = "sOmNuSoR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_MBCI_2147843546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.MBCI!MTB"
        threat_id = "2147843546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 06 08 8f ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df}  //weight: 1, accuracy: Low
        $x_1_2 = {72 11 00 00 70 20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 08 a2}  //weight: 1, accuracy: Low
        $x_1_3 = "a0acfd767f06" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ABNC_2147844202_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ABNC!MTB"
        threat_id = "2147844202"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 11 01 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 7e ?? ?? ?? 0a 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 1b 3a ?? ?? ?? 00 26 38 ?? ?? ?? 00 dd ?? ?? ?? 00 13 01 49 00 72 ?? ?? ?? 70 28 ?? ?? ?? 06 17 3a ?? ?? ?? 00 26 38 ?? ?? ?? 00 28}  //weight: 3, accuracy: Low
        $x_1_2 = "Replace" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "GetTypes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_EAO_2147845235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.EAO!MTB"
        threat_id = "2147845235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 9a 0c 08 16 18 6f ?? 00 00 0a 12 04 28 ?? 00 00 0a 26 11 04 18 d6 13 05 08 18 11 04 6f ?? 00 00 0a 08 16 11 05 6f ?? 00 00 0a 13 06 11 06 28 ?? 00 00 06 0c de 47 08 28 ?? 00 00 0a 13 07 28 ?? 00 00 0a 11 07 6f ?? 00 00 0a 0c de 30}  //weight: 2, accuracy: Low
        $x_1_2 = "VIRUS" wide //weight: 1
        $x_1_3 = "SANDBOX" wide //weight: 1
        $x_1_4 = "MALWARE" wide //weight: 1
        $x_1_5 = "SANDBOXIE" wide //weight: 1
        $x_1_6 = "FileMemory.mem" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ABRN_2147845550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ABRN!MTB"
        threat_id = "2147845550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReadAsByteArrayAsyn" ascii //weight: 1
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "Reverse" ascii //weight: 1
        $x_4_4 = {38 00 35 00 2e 00 33 00 31 00 2e 00 34 00 35 00 2e 00 34 00 32}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_CST_2147846589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.CST!MTB"
        threat_id = "2147846589"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 07 6f 06 00 00 0a 07 03 6f ?? ?? ?? ?? 5d 0c 03 08 6f ?? ?? ?? ?? 0d 09 61 d1 13 04 06 11 04 6f ?? ?? ?? ?? 26 07 17 58 0b 07 02 6f ?? ?? ?? ?? 32 cd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ABUQ_2147846603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ABUQ!MTB"
        threat_id = "2147846603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FromBase64String" ascii //weight: 1
        $x_1_2 = "Reverse" ascii //weight: 1
        $x_1_3 = "a16918ed-f03c-41d8-acab-6e263cbed770" ascii //weight: 1
        $x_2_4 = "protoolschile.cl/Xxqpzds.dat" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AAD_2147846722_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AAD!MTB"
        threat_id = "2147846722"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 16 0b 2b 3d 06 07 9a 6f 30 00 00 0a 7e 0d 00 00 04 28 2d 00 00 06 2c 05 28 2e 00 00 06 06 07 9a 6f 31 00 00 0a 7e 0e 00 00 04 28 2d 00 00 06 2c 05 28 2e 00 00 06 1f 64 28 32 00 00 0a 07 17 58 0b 07 06 8e 69 17 59 32 bb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_GIF_2147847237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.GIF!MTB"
        threat_id = "2147847237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 07 2b 2f 00 08 6f ?? ?? ?? 0a 11 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 16 91 13 08 09 11 08 6f ?? ?? ?? 0a 00 00 11 07 18 58 13 07 11 07 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a fe 04 13 09 11 09 2d bc}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ABXY_2147848238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ABXY!MTB"
        threat_id = "2147848238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {17 2c 04 2b 1c 2b 21 7e ?? 00 00 04 7e ?? 00 00 04 2b 18 2b 1d 2b 1e 2b 23 75 ?? 00 00 1b 2b 23 2a 28 ?? 00 00 06 2b dd 0a 2b dc 28 ?? 00 00 06 2b e1 06 2b e0 28 ?? 00 00 06 2b db 28 ?? 00 00 06 2b d6 28 ?? 00 00 06 2b d6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ABZH_2147848764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ABZH!MTB"
        threat_id = "2147848764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 06 2b 72 16 13 07 2b 61 16 13 08 2b 51 08 11 08 11 07 6f ?? 00 00 0a 13 09 16 13 0a 11 06}  //weight: 2, accuracy: Low
        $x_2_2 = {2b 1f 12 09 28 ?? 00 00 0a 13 0a 2b 14 12 09 28 ?? 00 00 0a 13 0a 2b 09 12 09 28 ?? 00 00 0a 13 0a 07 11 0a 6f ?? 00 00 0a 11 08 17 58 13 08 11 08 09 32 aa 11 07 17 58 13 07 11 07 11 04 32 99 11 06 17 58 13 06 11 06 19 32 89}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_CXJK_2147849331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.CXJK!MTB"
        threat_id = "2147849331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 13 08 16 13 09 11 08 12 09 28 ?? ?? ?? ?? 00 08 07 11 07 18 6f 17 00 00 0a 1f 10 28 18 00 00 0a 6f 19 00 00 0a 00 de 0d 11 09 2c 08 11 08 28 1a 00 00 0a 00 dc 00 11 07 18 58 13 07 11 07 07 6f 1b 00 00 0a fe 04 13 0a 11 0a 2d b2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_RDA_2147849610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.RDA!MTB"
        threat_id = "2147849610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 07 a2 6f a6 00 00 0a 75 27 00 00 01 13 04 11 04 72 ?? ?? ?? ?? 6f a7 00 00 0a 7e 56 00 00 04 13 0b 11 0b 28 a8 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AACS_2147849944_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AACS!MTB"
        threat_id = "2147849944"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "DTO.Properties.Resources" ascii //weight: 2
        $x_2_2 = "911f0061-e061-40b2-8021-2a2e4a4573fc" ascii //weight: 2
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AADX_2147850090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AADX!MTB"
        threat_id = "2147850090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 02 11 0a 11 03 18 28 ?? 00 00 06 1f 10 28 ?? 00 00 06 6f ?? 00 00 0a 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 3a ?? ff ff ff 26 20 00 00 00 00 38}  //weight: 4, accuracy: Low
        $x_1_2 = "Qomedsajzi" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_MBGM_2147850564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.MBGM!MTB"
        threat_id = "2147850564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 2c 11 07 07 09 58 08 11 04 58 6f ?? 00 00 0a 13 0a 12 0a 28 ?? 00 00 0a 13 08 11 06 11 05 11 08 9c 11 05 17 58 13 05 11 04 17 58 13 04 11 04 17 32 cf}  //weight: 1, accuracy: Low
        $x_1_2 = {16 13 05 20 01 ae 00 00 8d ?? 00 00 01 13 06 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_MBGN_2147850565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.MBGN!MTB"
        threat_id = "2147850565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 3a 16 13 07 2b 2a 09 11 04 11 06 58 11 05 11 07 58 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 13 09 08 07 11 09 9c 07 17 58 0b 11 07 17 58 13 07 11 07 17 32 d1}  //weight: 1, accuracy: Low
        $x_1_2 = "Zlm2023" wide //weight: 1
        $x_1_3 = "Aads.Sorts.He" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ASBK_2147850630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ASBK!MTB"
        threat_id = "2147850630"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 14 0c 38 ?? 00 00 00 00 28 ?? 00 00 06 0c dd ?? 00 00 00 26 dd ?? 00 00 00 08 2c eb}  //weight: 2, accuracy: Low
        $x_2_2 = {13 04 11 04 07 16 73 ?? 00 00 0a 13 05 11 05 09 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 06 dd ?? 00 00 00 11 05 39 ?? 00 00 00 11 05 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ASBL_2147851421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ASBL!MTB"
        threat_id = "2147851421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 16 13 04 2b 23 00 06 11 04 18 6f ?? 00 00 0a 13 05 07 11 04 18 5b 11 05 1f 10 28 ?? 00 00 0a d2 9c 00 11 04 18 58 13 04 11 04 06 6f ?? 00 00 0a fe 04 13 06 11 06 2d cd}  //weight: 1, accuracy: Low
        $x_1_2 = {32 00 2a 00 39 00 37 00 2a 00 43 00 36 00 2a 00 32 00 36 00 2a 00 44 00 36 00 2a 00 35 00 36 00 2a 00 33 00 37 00 2a 00 33 00 37 00 2a 00 31 00 34 00 2a 00 31}  //weight: 1, accuracy: High
        $x_1_3 = "72B72--2--****9883*11**21***69*4*3B1A2*A" wide //weight: 1
        $x_1_4 = "E25646F6D6--235F444--2E696--2E65727" wide //weight: 1
        $x_1_5 = {37 00 31 00 38 00 32 00 39 00 36 00 45 00 38 00 35 00 2d 00 2d 00 31 00 31 00 36 00 31 00 35 00 2d 00 2d 00 31 00 31 00 41 00 31 00 39 00 2d 00 2d 00 35 00 2d 00 2d 00 33 00 31 00 31 00 2d 00 2d 00 2a 00 2a 00 36 00 32 00 44 00 38 00 34}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_CXGG_2147851458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.CXGG!MTB"
        threat_id = "2147851458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DksuYjnKoRHAgIfRdjvsl974445418146477600042106778" wide //weight: 1
        $x_1_2 = "dCGDpJAxkxIZkJ934346500823380836483973976" wide //weight: 1
        $x_1_3 = "DutlAORhRJVfiVZCjuqjGXVjc960145579450557309387263802" wide //weight: 1
        $x_1_4 = "AUnrRRccmOUsJsOIQ7786052384152085672453645" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SDP_2147851808_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SDP!MTB"
        threat_id = "2147851808"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 50 06 02 50 07 91 9c 02 50 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e6 06 07 32 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AAII_2147852088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AAII!MTB"
        threat_id = "2147852088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 14 0b 28 ?? 00 00 06 0b 07 8e 69 8d ?? 00 00 01 0c 16 0d 38 ?? 00 00 00 08 09 07 09 91 06 09 06 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 07 8e 69 32 e0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AAIV_2147852350_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AAIV!MTB"
        threat_id = "2147852350"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 16 06 7b ?? 00 00 04 6f ?? 00 00 0a 28 ?? 00 00 0a 7e ?? 00 00 04 25 3a ?? 00 00 00 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 06 fe ?? ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 7e ?? 00 00 04 25 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_NAN_2147852428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.NAN!MTB"
        threat_id = "2147852428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 1a 11 1a 2c 30 11 04 72 ?? ?? 00 70 6f ?? ?? 00 0a 26 11 04 6f ?? ?? 00 0a 28 ?? ?? 00 0a 16 fe 01 13 1b 11 1b 2c 0d 11 04 6f ?? ?? 00 0a 28 ?? ?? 00 0a 26 00 72 ?? ?? 00 70 11 04 09 28 ?? ?? 00 0a 28 ?? ?? 00 0a 13 1c 11 1c 2c 24 02 7e ?? ?? 00 04 72 ?? ?? 00 70 6f ?? ?? 00 0a 09 6f ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 06 00 00 2b 18 00 08 16 9a 72 ?? ?? 00 70 11 04}  //weight: 5, accuracy: Low
        $x_1_2 = "Bosch-ECU-UltimaX-Tool" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_CXIJ_2147852660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.CXIJ!MTB"
        threat_id = "2147852660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6a5a90002400000023000000d8f" ascii //weight: 1
        $x_1_2 = "f00009f00000027000000670000" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AND_2147852834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AND!MTB"
        threat_id = "2147852834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 02 03 59 11 03 59 20 ff 00 00 00 5f d2 13 02 20 05 00 00 00 7e 16 00 00 04 7b 29 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AND_2147852834_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AND!MTB"
        threat_id = "2147852834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe 01 16 fe 01 13 42 11 42 2d 1e 00 14 13 0b 14 13 0c 11 0b 11 0c 6f ?? ?? ?? 0a 13 0d 14 13 0e 11 0e 6f ?? ?? ?? 0a 26 00 02 11 09 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AMAA_2147890320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AMAA!MTB"
        threat_id = "2147890320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 11 09 09 5d 13 0a 11 09 11 04 5d 13 0b 07 11 0a 91 13 0c 08 11 0b 6f ?? 00 00 0a 13 0d 07 11 09 17 58 09 5d 91 13 0e 11 0c 11 0d 11 0e 28 ?? 00 00 06 13 0f 07 11 0a 11 0f 20 00 01 00 00 5d d2 9c 00 11 09 17 59 13 09 11 09 16 fe 04 16 fe 01 13 10 11 10 2d a9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_NAD_2147891423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.NAD!MTB"
        threat_id = "2147891423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 2f 1e 2c 1d 20 ef be 66 06 25 2c 0a 61 2b 24 2b 26 7e 81 00 00 04 16 2d f0 59}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "RC2CryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_NAD_2147891423_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.NAD!MTB"
        threat_id = "2147891423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1f 10 6f 82 00 00 06 20 ?? ?? ?? 00 38 ?? ?? ?? ff 11 07 16 8c ?? ?? ?? 01 7e ?? ?? ?? 04 13 10 11 10 6f ?? ?? ?? 0a 26 38 ?? ?? ?? ff 02 7b ?? ?? ?? 04 16 28 ?? ?? ?? 06 20 ?? ?? ?? 00 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "GNOLC.g.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AARL_2147892403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AARL!MTB"
        threat_id = "2147892403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0b 20 14 56 50 09 28 ?? 00 00 06 28 ?? 00 00 06 20 33 56 50 09 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 06 13 04}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_MBJU_2147892787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.MBJU!MTB"
        threat_id = "2147892787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 18 5a 1f 16 58 0b 2b 4b 07 06 8e 69 5d 13 05 07 11 04 6f ?? 00 00 0a 5d 13 08 06 11 05 91 13 09 11 04 11 08 6f ?? 00 00 0a 13 0a 02 06 07}  //weight: 1, accuracy: Low
        $x_1_2 = {11 05 02 11 0c 28 ?? 00 00 06 9c 07 17 59 0b 07 16 fe 04 16 fe 01 13 0d 11 0d 2d a8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SPAQ_2147893074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SPAQ!MTB"
        threat_id = "2147893074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 09 07 09 91 06 59 d2 9c 09 17 58 0d 09 07 8e 69 32 ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SPXY_2147893569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SPXY!MTB"
        threat_id = "2147893569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 06 8e 69 5d 13 05 07 11 04 6f ?? ?? ?? 0a 5d 13 09 06 11 05 91 13 0a 11 04 11 09 6f ?? ?? ?? 0a 13 0b 02 06 07 28 ?? ?? ?? 06 13 0c 02 11 0a 11 0b 11 0c 28 ?? ?? ?? 06 13 0d 06 11 05 02 11 0d 28 ?? ?? ?? 06 9c 07 17 59 0b 07 16 fe 04 16 fe 01 13 0e 11 0e 2d a8}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SPJR_2147893582_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SPJR!MTB"
        threat_id = "2147893582"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 11 04 16 6f ?? ?? ?? 0a 13 05 12 05 28 ?? ?? ?? 0a 13 06 09 11 06 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 08 6f ?? ?? ?? 0a 32 d4 09 6f ?? ?? ?? 0a 13 07 dd 0d 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AMAB_2147893930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AMAB!MTB"
        threat_id = "2147893930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 17 58 20 00 01 00 00 5d 13 04 11 05 07 11 04 91 58 20 00 01 00 00 5d 13 05 07 11 04 91 0d 07 11 04 07 11 05 91 9c 07 11 05 09 9c 07 11 04 91 07 11 05 91 58 20 00 01 00 00 5d 13 07 02 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 07 11 07 91 61 d2 81 ?? 00 00 01 11 06 17 58 13 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AMAB_2147893930_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AMAB!MTB"
        threat_id = "2147893930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 11 00 6f ?? 00 00 0a 11 00 28 ?? 00 00 06 28 ?? 00 00 06 13 08 20 02 00 00 00 7e ?? 08 00 04 7b ?? 08 00 04 39}  //weight: 5, accuracy: Low
        $x_5_2 = {11 07 11 08 16 73 ?? 00 00 0a 13 0c 20 00 00 00 00 7e ?? 08 00 04 7b ?? 08 00 04 3a ?? 00 00 00 26 20 00 00 00 00 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AAUF_2147894290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AAUF!MTB"
        threat_id = "2147894290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {72 2b 00 00 70 0a 06 20 f7 07 00 00 0c 12 02 28 ?? 00 00 0a 1f 54 0c 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 07}  //weight: 3, accuracy: Low
        $x_1_2 = "//I//n//v//o//k//e//" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_PTAB_2147894415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.PTAB!MTB"
        threat_id = "2147894415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 28 1c 00 00 06 7d 0b 00 00 04 06 7b 0b 00 00 04 2c ed}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ADG_2147896067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ADG!MTB"
        threat_id = "2147896067"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 07 6f 06 00 00 0a 07 03 6f ?? ?? ?? 0a 5d 0c 03 08 6f 06 00 00 0a 0d 09 61 d1 13 04 06 11 04 6f ?? ?? ?? 0a 26 07 17 58 0b 07 02 6f ?? ?? ?? 0a 32}  //weight: 10, accuracy: Low
        $x_3_2 = "_DR@MLW" ascii //weight: 3
        $x_3_3 = "~QCs@MQD" ascii //weight: 3
        $x_2_4 = "Decrypt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_GJW_2147896109_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.GJW!MTB"
        threat_id = "2147896109"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2b 18 06 08 2b 09 06 18 6f ?? ?? ?? 0a 2b 07 6f ?? ?? ?? 0a 2b f0 02 0d 2b 03 0c 2b e5 06 6f ?? ?? ?? 0a 09 16 09 8e 69 6f ?? ?? ?? 0a 13 04 de 14}  //weight: 10, accuracy: Low
        $x_1_2 = "TripleDESCryptoServiceProvider" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AMBF_2147897402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AMBF!MTB"
        threat_id = "2147897402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 07 11 04 5d 13 08 11 07 1f 16 5d 13 09 11 07 17 58 11 04 5d 13 0a 07 11 08 91 13 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AMCH_2147898997_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AMCH!MTB"
        threat_id = "2147898997"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 00 11 05 11 00 11 01 11 05 59 17 59 91 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AMMH_2147908310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AMMH!MTB"
        threat_id = "2147908310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 04 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 07 73 ?? 00 00 0a 13 07 11 07 11 05 16 73 ?? 00 00 0a 13 08 11 08 11 06 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 0b dd}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SPNN_2147908643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SPNN!MTB"
        threat_id = "2147908643"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {5d 13 08 07 08 91 11 07 61 07 11 08 91 59 20 00 01 00 00 58 13 09 07 08 11 09 20 ff 00 00 00 5f d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SPFM_2147911231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SPFM!MTB"
        threat_id = "2147911231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 58 08 5d 13 ?? 07 11 ?? 91 13 ?? 02 07 11 ?? 91 11 ?? 61 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ARA_2147915975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ARA!MTB"
        threat_id = "2147915975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 03 08 03 8e 69 5d 94 0d 06 09 91 13 04 06 09 06 08 91 9c 06 08 11 04 9c 00 08 17 59 0c 08 16 fe 04 16 fe 01 13 05 11 05 2d d5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ARA_2147915975_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ARA!MTB"
        threat_id = "2147915975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 06 11 07 11 06 11 07 91 1b 59 20 00 01 00 00 58 20 ?? ?? ?? ?? 5a 20 00 01 00 00 5d d2 9c 11 06 11 07 8f ?? ?? ?? ?? 25 47 03 09 58 20 00 01 00 00 5d d2 61 d2 52 00 11 07 17 58 13 07 11 07 11 06 8e 69 fe 04 13 08 11 08 2d b3}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ARA_2147915975_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ARA!MTB"
        threat_id = "2147915975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "UnitConverter.UnitConverter.resources" ascii //weight: 2
        $x_2_2 = "UnitConverter1.NodesControl.resources" ascii //weight: 2
        $x_2_3 = "UnitConverter1.Properties.Resources" ascii //weight: 2
        $x_1_4 = "keyEventArgs" ascii //weight: 1
        $x_1_5 = "NodesControl_MouseMove" ascii //weight: 1
        $x_1_6 = "add_MouseClick" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_NA_2147916490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.NA!MTB"
        threat_id = "2147916490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 11 04 11 05 02 08 11 05 58 91 03 11 05 07 5d 91 61 d2 9c 00 11 05 17 58}  //weight: 4, accuracy: High
        $x_1_2 = "VertexData" ascii //weight: 1
        $x_1_3 = "encryptedData" ascii //weight: 1
        $x_1_4 = "Decrypt" ascii //weight: 1
        $x_1_5 = "GetBytesAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_NB_2147916503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.NB!MTB"
        threat_id = "2147916503"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 06 8e 69 17 58 11 06 9e 11 06 06 16 95 61}  //weight: 5, accuracy: High
        $x_1_2 = "TextFrom" ascii //weight: 1
        $x_1_3 = "encryptedData" ascii //weight: 1
        $x_1_4 = "ShowPairs" ascii //weight: 1
        $x_1_5 = "password" ascii //weight: 1
        $x_1_6 = "ConvertStringToUintArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_KAC_2147920816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.KAC!MTB"
        threat_id = "2147920816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 58 20 00 01 00 00 5d 13 07 02 11 06 8f 16 00 00 01 25 71 ?? 00 00 01 07 11 07 91 61 d2 81 ?? 00 00 01 11 06 17 58 13 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_EM_2147928046_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.EM!MTB"
        threat_id = "2147928046"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FUCKMACS" ascii //weight: 1
        $x_1_2 = "DebuggerHiddenAttribute" ascii //weight: 1
        $x_1_3 = "EnsureSuccessStatusCode" ascii //weight: 1
        $x_1_4 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_5 = "get_NetworkInterfaceType" ascii //weight: 1
        $x_1_6 = "0bf582eb-df3f-46ba-97a6-8d8caaf4113d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AAGA_2147928177_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AAGA!MTB"
        threat_id = "2147928177"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 72 15 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 47 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0b 14 0c}  //weight: 3, accuracy: Low
        $x_2_2 = {07 08 16 08 8e 69 6f ?? 00 00 0a 0d}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AYA_2147930958_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AYA!MTB"
        threat_id = "2147930958"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "sudovpn.su/macs/Dnames/R/gate.php" wide //weight: 2
        $x_1_2 = "NetInt\\obj\\Release\\NetInt.pdb" ascii //weight: 1
        $x_1_3 = "$c0f9fb8d-a947-4ad0-844d-7af6f4a80784" ascii //weight: 1
        $x_1_4 = "Data successfully sent to the gate." wide //weight: 1
        $x_1_5 = "Error reading driver information from the registry" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SWA_2147931286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SWA!MTB"
        threat_id = "2147931286"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 7b 06 00 00 04 06 8f 03 00 00 02 28 09 00 00 06 06 17 58 0a 06 6e 17 02 7b 07 00 00 04 1f 1f 5f 62 6a 32 db}  //weight: 2, accuracy: High
        $x_2_2 = {06 17 62 02 7b 06 00 00 04 06 8f 03 00 00 02 03 28 0a 00 00 06 58 0a 07 17 59 0b 07 16 30 e1 06 17 02 7b 07 00 00 04 1f 1f 5f 62 59 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AMCZ_2147932344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AMCZ!MTB"
        threat_id = "2147932344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0d 09 08 6f ?? 00 00 0a 09 18 6f ?? 00 00 0a 09 6f ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 13 04 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_MBWQ_2147932551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.MBWQ!MTB"
        threat_id = "2147932551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {05 63 00 72 00 00 05 72 00 72 00 00 21 47 00 65 00 74 00 45 00 78 00 70 00 6f 00 72 00 74 00 65 00 64 00 54 00 79 00 70 00 65 00 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_EAOX_2147934436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.EAOX!MTB"
        threat_id = "2147934436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 11 06 11 07 11 06 11 07 91 19 63 11 06 11 07 91 1b 62 60 d2 9c 11 06 11 07 8f 1c 00 00 01 25 47 03 11 07 91 61 d2 52 00 11 07 17 58 13 07 11 07 06 fe 04 13 08 11 08 2d c6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SEB_2147937045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SEB!MTB"
        threat_id = "2147937045"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5f 62 60 20 b4 d5 fd 61 59 20 ca a9 00 00 20 ab a9 00 00 59 5f 64 60 72 24 06 00 70 a2 28 17 00 00 0a d0 03 00 00 02 28 14 00 00 0a 6f 6b 00 00 0a 73 6c 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SIM_2147937261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SIM!MTB"
        threat_id = "2147937261"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 20 03 e5 36 19 28 09 00 00 06 07 6f 12 00 00 06 74 1b 00 00 01 0d 02 09 02 7b 0d 00 00 04 6f 16 00 00 06}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SIR_2147939382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SIR!MTB"
        threat_id = "2147939382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 16 02 8e 69 6f 27 00 00 0a 6f 28 00 00 0a 6f 29 00 00 0a 7e 08 00 00 04 20 25 01 00 00 7e 08 00 00 04 20 25 01 00 00 94 7e 02 00 00 04 20 18 02 00 00 94 61 20 8c 00 00 00 5f 9e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SLU_2147939386_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SLU!MTB"
        threat_id = "2147939386"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 09 00 00 06 0a 73 0f 00 00 0a 25 02 06 28 08 00 00 06 6f 10 00 00 0a 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AFTA_2147940977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AFTA!MTB"
        threat_id = "2147940977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 1a 8d ?? 00 00 01 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 11 04 8d ?? 00 00 01 13 06 16 13 07 38 ?? 00 00 00 11 07 11 05 11 06 11 07 11 04 11 07 59 6f ?? 00 00 0a 58 13 07 11 07 11 04 32 e5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AKTA_2147941068_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AKTA!MTB"
        threat_id = "2147941068"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 8e 69 1a 3c 07 00 00 00 16 0b dd 70 00 00 00 72 ?? ?? 00 70 28 ?? 00 00 0a 0c 72 ?? ?? 00 70 28 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 03 72 ?? ?? 00 70 11 05 06 16 06 8e 69 6f ?? 00 00 0a 6f ?? 00 00 06 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AVTA_2147941400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AVTA!MTB"
        threat_id = "2147941400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 8e 69 1a 3c ?? 00 00 00 16 0b dd ?? 00 00 00 72 ?? ?? 00 70 28 ?? 00 00 0a 0c 72 ?? ?? 00 70 28 ?? 00 00 0a 0d 28 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 03 11 05 6f ?? 00 00 0a 6f ?? 00 00 06 17 0b dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ABYA_2147945113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ABYA!MTB"
        threat_id = "2147945113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 08 06 08 91 03 08 03 8e 69 5d 91 61 d2 9c 16 0d 2b 18 06 08 06 08 91 03 09 91 07 1f 1f 5f 62 09 61 08 58 61 d2 9c 09 17 58 0d 09 03 8e 69 32 e2 08 17 58 0c 08 06 8e 69 32}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AB_2147945965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AB!MTB"
        threat_id = "2147945965"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 7d 1b 00 00 04 20 2f 00 00 00 38 7d fa ff ff 7e 16 00 00 04 20 93 33 d3 d6 65 20 03 00 00 00 62 20 c7 88 e4 2f 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_MCF_2147947467_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.MCF!MTB"
        threat_id = "2147947467"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 00 53 00 67 00 2b 00 50 00 43 00 7a 00 66 00 65 00 46 00 67 00 3d 00 3d 00 00 19 48 00 68 00 6c 00 6e 00 6f 00 39 00 64 00 51 00 51 00 67 00 38 00 3d 00 00 4b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_STT_2147947766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.STT!MTB"
        threat_id = "2147947766"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "4s/6hOAAvE2xNeyyxM4ODA==" wide //weight: 2
        $x_1_2 = "Lipaqii.Properties.Resources" wide //weight: 1
        $x_1_3 = "Dhjekhla" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_AACB_2147948829_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.AACB!MTB"
        threat_id = "2147948829"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 91 02 28 ?? 00 00 06 61 d2 0c 7e ?? 00 00 04 08 6f ?? 00 00 0a 07 17 58 0b 07 06 8e 69 17 59 32 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SLCV_2147950818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SLCV!MTB"
        threat_id = "2147950818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 00 28 67 00 00 06 7e 04 00 00 04 7e 05 00 00 04 72 01 00 00 70 72 ?? 00 00 70 6f 4d 00 00 06 38 00 00 00 00 dd ?? ff ff ff 26 38 00 00 00 00 dd ?? ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_KK_2147951760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.KK!MTB"
        threat_id = "2147951760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {11 00 28 67 00 00 06 7e 04 00 00 04 7e 05 00 00 04 72 01 00 00 70 72 ?? 00 00 70 6f 4d 00 00 06 38 00 00 00 00 dd ?? ff ff ff 26 38 00 00 00 00 dd ?? ff ff ff 38 ?? ff ff ff}  //weight: 20, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_SLQA_2147957234_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.SLQA!MTB"
        threat_id = "2147957234"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 12 00 00 06 7e 04 00 00 04 7e 05 00 00 04 28 08 00 00 06 28 02 00 00 0a 6f 03 00 00 0a 13 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_PGAD_2147957483_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.PGAD!MTB"
        threat_id = "2147957483"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 12 00 00 06 7e 04 00 00 04 7e 05 00 00 04 28 08 00 00 06 28 02 00 00 0a 6f 03 00 00 0a 13}  //weight: 5, accuracy: High
        $x_5_2 = {00 70 d0 06 00 00 02 28 18 00 00 0a 6f 19 00 00 0a 73 1a 00 00 0a 80 07 00 00 04 [0-63] 1a 7e 08 00 00 04 2a 00 1e 02 80 08 00 00 04 2a 6a 28 0f 00 00 06 72 ?? 00 00 70 7e 08 00 00 04 6f 1b 00 00 0a 74 01 00 00 1b 2a 00 26 7e 09 00 00 04 14 fe 01 2a 00 00 1a 7e 09 00 00 04 2a 00 1e 02 28 17 00 00 0a 2a 1a 28 17 00 00 06 2a 00 13 30 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_GTD_2147958994_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.GTD!MTB"
        threat_id = "2147958994"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 0a 18 6f ?? 00 00 0a 38 0c 00 00 00 73 ?? 00 00 0a 13 01 38 ?? 00 00 00 11 0a 03 6f ?? 00 00 0a 38 ?? ?? ?? ?? 00 11 01 11 0a 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 0b 38 00 00 00 00 00 11 0b 02 16 02 8e 69}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Androm_ARR_2147959625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Androm.ARR!MTB"
        threat_id = "2147959625"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Androm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "$4427d5a3-599e-44f6-aff3-e08afc0bafad" ascii //weight: 6
        $x_3_2 = "<Module>{d2048a9c-6647-4b07-ae32-46459aa70e3c}" ascii //weight: 3
        $x_10_3 = "Cjmtydpk.exe" ascii //weight: 10
        $x_1_4 = "SdKBHB3/hp+w6+oaoKp1HA==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

