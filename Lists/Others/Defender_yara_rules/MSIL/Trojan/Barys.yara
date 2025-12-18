rule Trojan_MSIL_Barys_ALB_2147843056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.ALB!MTB"
        threat_id = "2147843056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 06 8e b7 17 da 13 0a 13 08 2b 13 06 11 08 06 11 08 91 08 11 08 91 61 9c 11 08 17 d6 13 08 11 08 11 0a 31 e7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_ABS_2147843942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.ABS!MTB"
        threat_id = "2147843942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 0f 2b 38 11 0e 11 0f 9a 13 10 00 11 10 6f ?? ?? ?? 0a 7e 0f 00 00 04 16 28 ?? ?? ?? 0a 16 fe 01 13 11 11 11 13 12 11 12 2c 0a 00 11 10 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_GJI_2147847785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.GJI!MTB"
        threat_id = "2147847785"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cHM6Ly9hdXRoLnVua25vd25wLm9uZS8/Z2FtZWhlbHBlcnM=" ascii //weight: 1
        $x_1_2 = "Rm9yY2VVcGRhdGVGcm9tTVU=" ascii //weight: 1
        $x_1_3 = "d2RmaWx0ZXI=" ascii //weight: 1
        $x_1_4 = "WGJsR2FtZVNhdmU=" ascii //weight: 1
        $x_1_5 = "del /s /f /q C:\\Windows\\Prefetch" ascii //weight: 1
        $x_1_6 = "C:\\pkey" ascii //weight: 1
        $x_1_7 = "powershell" ascii //weight: 1
        $x_1_8 = "YOUR ANTIVIRUS IS BLOCKING THE LOADER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_PSTE_2147851663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.PSTE!MTB"
        threat_id = "2147851663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6FDC1DBD" ascii //weight: 1
        $x_1_2 = "236E784D" ascii //weight: 1
        $x_1_3 = "4C060D49" ascii //weight: 1
        $x_1_4 = "39E831C6" ascii //weight: 1
        $x_1_5 = "242C056B" ascii //weight: 1
        $x_1_6 = "25047629" ascii //weight: 1
        $x_1_7 = "ComputeHash" ascii //weight: 1
        $x_1_8 = "DownloadString" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "GetExecutingAssembly" ascii //weight: 1
        $x_1_11 = "WriteInt64" ascii //weight: 1
        $x_1_12 = "get_UTF8" ascii //weight: 1
        $x_1_13 = "BlockCopy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_ARA_2147851981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.ARA!MTB"
        threat_id = "2147851981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 2, accuracy: High
        $x_2_2 = "oHUEK.resources" ascii //weight: 2
        $x_2_3 = "ykmBF.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_ARA_2147851981_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.ARA!MTB"
        threat_id = "2147851981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 17 11 19 58 06 11 19 58 47 11 05 11 19 11 05 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 61 d2 52 00 11 19 17 58 13 19 11 19 11 10 8e 69 fe 04 13 1a 11 1a 2d cc}  //weight: 2, accuracy: Low
        $x_2_2 = "<SHIELD>" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AMAC_2147852297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AMAC!MTB"
        threat_id = "2147852297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 20 00 01 00 00 6f ?? 00 00 0a 06 72 ?? ?? ?? ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? ?? ?? ?? 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_PSUL_2147852639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.PSUL!MTB"
        threat_id = "2147852639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 36 00 00 01 13 04 7e 43 00 00 04 02 1a 58 11 04 16 08 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AMAB_2147852930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AMAB!MTB"
        threat_id = "2147852930"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Program Files\\PUBG\\pkey" ascii //weight: 1
        $x_1_2 = "YhTXD4CjsLH55xCVVKTbkN3DEFm6bVVz6jRMPc9N0YGXZjO4ur" ascii //weight: 1
        $x_1_3 = "Disable your Anti-Virus.." ascii //weight: 1
        $x_1_4 = "## Download finished!" ascii //weight: 1
        $x_1_5 = "C:\\pkey" ascii //weight: 1
        $x_1_6 = "PLoader.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_RDA_2147887427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.RDA!MTB"
        threat_id = "2147887427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 7e 00 00 0a 6f 80 00 00 0a 06 06 6f 81 00 00 0a 06 6f 82 00 00 0a 6f 83 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AMAD_2147888788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AMAD!MTB"
        threat_id = "2147888788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 13 04 73 ?? 00 00 0a 0b 07 11 04 17 73 ?? 00 00 0a 0c 28 ?? ?? 00 06 16 9a 75 ?? 00 00 1b 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 05 de 18}  //weight: 1, accuracy: Low
        $x_1_2 = "9bz8gr3p6yfttbls87kx6up8dff7jmq7" ascii //weight: 1
        $x_1_3 = "Mp3LameAudioEncoder" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AB_2147889174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AB!MTB"
        threat_id = "2147889174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 03 2a 11 02 18 58 13 02 20 01 00 00 00 7e 6a 00 00 04 7b 0a 00 00 04 3a 92 ff ff ff 26 20 01 00 00 00 38 87 ff ff ff 11 03 11 02 18 5b 02 11 02 18}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_PSWW_2147890096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.PSWW!MTB"
        threat_id = "2147890096"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 14 8e 69 28 ?? 00 00 0a 11 0c 11 06 11 12 6a 58 11 14 11 14 8e 69 16 6a 28 ?? 00 00 06 26 11 10 17 58 68 13 10 11 10 11 04 32 87}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AMAF_2147892946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AMAF!MTB"
        threat_id = "2147892946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 1b 11 09 11 21 11 23 61 11 1a 19 58 61 11 2e 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AMAF_2147892946_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AMAF!MTB"
        threat_id = "2147892946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 17 d2 13 2f 11 17 1e 63 d1 13 17 11 1e 11 09 91 13 21 11 1e 11 09 11 24 11 21 61 19 11 18 58 61 11 2f 61 d2 9c 11 09 17 58 13 09 11 21 13 18 11 09 11 26 32 a4}  //weight: 5, accuracy: High
        $x_5_2 = {11 32 11 13 11 11 11 13 91 9d 11 13 17 58 13 13 11 13 11 1b 32 ea}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_ABR_2147895208_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.ABR!MTB"
        threat_id = "2147895208"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 02 08 07 06 1b 16 09 28 0f 00 00 06 26 06 6f 18 00 00 0a 13}  //weight: 2, accuracy: High
        $x_1_2 = "LimeLogger.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AMBA_2147895790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AMBA!MTB"
        threat_id = "2147895790"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {de 03 26 de 00 72 ?? 00 00 70 28 ?? 00 00 0a 73 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 74 ?? 00 00 1b 28 ?? 00 00 2b 28 ?? 00 00 2b 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 14 16 8d ?? 00 00 01 6f ?? 00 00 0a 26 de 03}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 2c 10 06 16 31 0c 06 20 ?? 03 00 00 5a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_NL_2147897304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.NL!MTB"
        threat_id = "2147897304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 20 16 00 00 00 38 07 ?? ?? ?? 11 44 02 58 20 e2 ?? ?? ?? 11 00 59 11 01 61 61 11 0c 20 93 ?? ?? ?? 11 00 58 11 01 58 5f 61 13 41}  //weight: 1, accuracy: Low
        $x_1_2 = {11 1e 8e 69 13 27 20 0e 00 00 00 38 2a ?? ?? ?? 11 1e 11 09 11 25 11 23 61 19 11 1d 58 61 11 2b 61 d2 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_NL_2147897304_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.NL!MTB"
        threat_id = "2147897304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 02 1a 62 11 02 1b 63 61 11 02 58 11 03 11 00 11 03 19 5f 94 58 61 58 13 07 20 0a 00 00 00 38 e5 fd ff ff}  //weight: 1, accuracy: High
        $x_1_2 = {11 07 02 58 11 00 20 22 ?? ?? ?? 58 11 01 59 61 11 0c 20 63 ?? ?? ?? 11 00 59 11 01 58 5f 61 13 41 20 4f 00 00 00 38 68 e6 ff ff 17 11 09 5f 3a b9 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {11 1f 11 09 11 24 11 27 61 19 11 18 58 61 11 2f 61 d2 9c 20 05 00 00 00 7e 54 00 00 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_N_2147898268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.N!MTB"
        threat_id = "2147898268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {1f 09 11 07 1f 09 95 08 1f 09 95 61 9e 11 07 1f 0a 11 07 1f 0a 95 08 1f 0a 95 61 9e 11 0c 20 e2 e4 c7 d2 5a 20 c4 9a 28 30 61 38 b9 fc ff ff}  //weight: 5, accuracy: High
        $x_5_2 = {16 11 07 16 95 08 16 95 61 9e 11 07 17 11 07 17 95 08 17 95 61 9e 11 0c 20 f9 99 00 7a 5a 20 6f a4 20 6e 61 38 ea fc ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_PSCZ_2147899344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.PSCZ!MTB"
        threat_id = "2147899344"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 11 06 28 06 00 00 06 13 07 11 07 11 05 6f 20 ?? ?? ?? 1f 20 0d 15 6a 13 08 28 21 ?? ?? ?? 13 09 06 11 07 6f 22 ?? ?? ?? 16 73 23 ?? ?? ?? 13 0a 7e 24 ?? ?? ?? 11 09 17 73 23 ?? ?? ?? 13 0b}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateInstance" ascii //weight: 1
        $x_1_3 = "CryptoStreamMode" ascii //weight: 1
        $x_1_4 = "ICryptoTransform" ascii //weight: 1
        $x_1_5 = "SymmetricAlgorithm" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AAAJ_2147899679_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AAAJ!MTB"
        threat_id = "2147899679"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 03 8e 69 5d 1f 0a 59 1f 0a 58 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 61 28 ?? 00 00 0a 03 08 20 89 10 00 00 58 20 88 10 00 00 59 03 8e 69 5d 91 59 20 ff 00 00 00 58 17 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_PTEU_2147900327_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.PTEU!MTB"
        threat_id = "2147900327"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 6c 03 00 00 28 ?? 00 00 2b 13 0c 1f 19 13 30 1f 31 13 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_PTGK_2147900961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.PTGK!MTB"
        threat_id = "2147900961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {ff ff 11 34 28 ?? 00 00 06 80 03 00 00 04 11 39 20 7f 16 21 66 5a 20 b6 c8 80 bb}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_SG_2147901488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.SG!MTB"
        threat_id = "2147901488"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DL_And_P_RTK" ascii //weight: 1
        $x_1_2 = "Nw_ET_P" ascii //weight: 1
        $x_1_3 = "WFA1.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_DLAA_2147902317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.DLAA!MTB"
        threat_id = "2147902317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 06 11 04 28 ?? 00 00 06 0d 06 11 04 28 ?? 00 00 06 13 05 11 05 17 da 17 d6 8d ?? 00 00 01 0c 09 08 16 11 05 28 ?? 00 00 0a 08 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_NN_2147902545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.NN!MTB"
        threat_id = "2147902545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 e0 95 58 ?? ?? ?? ?? ?? 0e 06 17 59 e0 95 58 0e 05 28 e9 0d ?? ?? 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_CCHT_2147903469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.CCHT!MTB"
        threat_id = "2147903469"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "<CheckAV>" ascii //weight: 1
        $x_1_2 = "<GetScreenshot>" ascii //weight: 1
        $x_1_3 = "<GetClipboard>" ascii //weight: 1
        $x_1_4 = "<get_tokens>" ascii //weight: 1
        $x_1_5 = "<heartbeat>" ascii //weight: 1
        $x_1_6 = "<ShellCommand>" ascii //weight: 1
        $x_1_7 = "Discord_rat" ascii //weight: 1
        $x_1_8 = "rootkit" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_ND_2147904795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.ND!MTB"
        threat_id = "2147904795"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 06 58 8f 27 00 00 02 04 28 ?? 01 00 06 0d 06 17 62 0a 06 09 58 0a 07 09 08}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AMMC_2147904834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AMMC!MTB"
        threat_id = "2147904834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 11 b0 18 6f ?? 00 00 0a 11 b0 17 6f ?? 00 00 0a 11 b0 6f ?? 00 00 0a 02 16 02 8e b7 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_GPA_2147907836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.GPA!MTB"
        threat_id = "2147907836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 8e 69 5d [0-32] 17 58 09 5d 91 59}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_MAAA_2147909374_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.MAAA!MTB"
        threat_id = "2147909374"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 01 00 00 8d 25 00 00 01 13 05 16 13 07 11 0e 20 82 bd 8c b3 5a 20 51 53 e2 48 61 38 73 fe ff ff 11 05 16 11 04 11 07 11 06 28 ?? 00 00 06 11 07 11 06 58 13 07}  //weight: 2, accuracy: Low
        $x_2_2 = {ff ff 12 09 28 ?? 00 00 0a 74 01 00 00 1b 13 0a 11 0e 20 53 92 17 fb 5a 20 b3 03 3e 75 61 38 b9 fd ff ff 11 04 11 08 28 ?? 00 00 06 13 09 11 0e 20 fc 26 0e 21 5a 20 75 e9 a0 d3 61 38}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AMMH_2147911853_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AMMH!MTB"
        threat_id = "2147911853"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 16 5d 91 13 ?? 02 07 11 ?? 91 11 ?? 61 07 11 ?? 17 58 07 8e 69 5d 91 20 ff 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_RPAA_2147916121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.RPAA!MTB"
        threat_id = "2147916121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 03 08 20 0f 02 00 00 58 20 0e 02 00 00 59 18 59 18 58 03 8e 69 5d 1f 09 58 1f 0b 58 1f 14 59 91 59 20 fb 00 00 00 58 1b 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_NG_2147921845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.NG!MTB"
        threat_id = "2147921845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 06 07 03 61 d1 ?? ?? 00 00 0a 26 09 17 58 0d 09 08}  //weight: 2, accuracy: Low
        $x_1_2 = {0a 06 18 5d 2d 06 06 18 5d 17 2e 0a 06 19}  //weight: 1, accuracy: High
        $x_1_3 = "*K*E*R*N*E*L*3*2*.*D*L*L*" ascii //weight: 1
        $x_1_4 = "Debugger.IsAttached || IsDebuggerPresent()" ascii //weight: 1
        $x_1_5 = "DynamicAntiDebug" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_SK_2147925573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.SK!MTB"
        threat_id = "2147925573"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$8b52ef8f-61b3-4ce3-8cee-6199efc29786" ascii //weight: 1
        $x_1_2 = "ZeusCrypter\\obj\\Debug\\ZeusCrypter.pdb" ascii //weight: 1
        $x_1_3 = "Write path to file to encrypt" ascii //weight: 1
        $x_1_4 = "Crypted.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_EA_2147927333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.EA!MTB"
        threat_id = "2147927333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "$676b9b57-ed95-4388-ba83-0b2cafdf836b" ascii //weight: 3
        $x_3_2 = "powershell -windowstyle hidden (Start-Process -FilePath $env:" wide //weight: 3
        $x_2_3 = "OQAzADEANAAzADAAMgA4ADIAMgA=" wide //weight: 2
        $x_2_4 = "UwBlAHIAdgBlAHIALgBWAGIAcwA=" wide //weight: 2
        $x_2_5 = "VABFAE0AUAA=" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_PAMR_2147929494_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.PAMR!MTB"
        threat_id = "2147929494"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "~&h&lgdAdK.M?d+;X[*!}X}&X_;_Zd+j&.&d}1}loexxd/dzlecqBez" wide //weight: 3
        $x_2_2 = "~qoq>_dAd^BFcdVX_;,;BRx}BFUR>_" wide //weight: 2
        $x_2_3 = "kV99o;>e_;FXJe_ek" wide //weight: 2
        $x_2_4 = "+;X[*!J;xGJB;,q" wide //weight: 2
        $x_2_5 = "$4a2f8fb6-1077-469a-9246-736e6afe8da1" ascii //weight: 2
        $x_1_6 = "klFFG;qxk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_NBA_2147931871_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.NBA!MTB"
        threat_id = "2147931871"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {95 2e 03 16 2b 05 17 11 1b 13 1b 17 59}  //weight: 2, accuracy: High
        $x_1_2 = {11 3d 2c 03 16 2b 01 17 17 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_PHT_2147934640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.PHT!MTB"
        threat_id = "2147934640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 02 1f 10 63 20 ?? 00 00 00 5f d2 9c 25 17 02 1e 63 20 ?? 00 00 00 5f d2 9c 25 18 02 20 ?? 00 00 00 5f d2 9c 0b 07 2a}  //weight: 6, accuracy: Low
        $x_5_2 = {0a 25 17 6f ?? 00 00 0a 0a 06 6f ?? 00 00 0a 0f 00 28 ?? 00 00 0a 1f 10 62 0f 00 28 ?? 00 00 0a 1e 62 60 0f 00 28 ?? 00 00 0a 60 0b 07 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_SLYT_2147941290_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.SLYT!MTB"
        threat_id = "2147941290"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8e 69 39 16 00 00 00 17 8d 01 00 00 01 0d 09 16 16 8d 18 00 00 01 a2 09 38 01 00 00 00 14 0c 07 14 08 6f 16 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_ZABY_2147941597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.ZABY!MTB"
        threat_id = "2147941597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 0b 07 28 ?? 00 00 06 13 05 11 05 72 49 00 00 70 1b 8d ?? 00 00 01 13 0b 11 0b 16 72 3f 01 00 70 a2 11 0b 17 72 45 01 00 70 a2 11 0b 18 72 4d 01 00 70 a2 11 0b 19 72 51 01 00 70 a2 11 0b 1a 72 57 01 00 70}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_A_2147945978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.A!MTB"
        threat_id = "2147945978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0e 0a 00 fe 0c 18 00 20 2d 31 7e 18 5a 20 6a c8 b2 df 61 38 61 ef ff ff 20 c1 fc fb 36 20 03 00 00 00 20 c4 2d 00 00 5a 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AXBB_2147948708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AXBB!MTB"
        threat_id = "2147948708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0a 06 7e 01 00 00 04 7e 02 00 00 04 6f ?? 00 00 0a 0b 7e ?? 00 00 04 6f ?? 00 00 0a 0c 07 08 16 08 8e 69 6f ?? 00 00 0a 0d 09 13 04 2b 00 11 04 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_SLFH_2147949346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.SLFH!MTB"
        threat_id = "2147949346"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 73 30 00 00 0a 13 05 28 31 00 00 0a 72 1b 00 00 70 28 32 00 00 0a 6f 33 00 00 0a 13 06 02 73 34 00 00 0a 13 07 09 11 06 6f 35 00 00 0a 26 09 11 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_SLWQ_2147954523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.SLWQ!MTB"
        threat_id = "2147954523"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Stop-Process -Name 'SecurityHealthSystray' -Force -ErrorAction SilentlyContinue" wide //weight: 2
        $x_2_2 = "Add-MpPreference -ExclusionProcess 'svchost.exe'" wide //weight: 2
        $x_2_3 = "Add-MpPreference -ExclusionProcess '$77kit.exe'" wide //weight: 2
        $x_2_4 = "-NoProfile -ExecutionPolicy Bypass -File \"" wide //weight: 2
        $x_2_5 = "Add-MpPreference -ExclusionPath ($env:USERPROFILE + '\\AppData\\Local\\Temp')" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_ZRM_2147954904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.ZRM!MTB"
        threat_id = "2147954904"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {10 00 00 01 06 07 03 6f ?? 00 00 0a 5d 91 07 1b 58 06 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 ?? 10 00 00 01 07 17 58 0b 07 02 8e 69 32 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_SL_2147954964_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.SL!MTB"
        threat_id = "2147954964"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 00 28 75 00 00 06 7e 04 00 00 04 7e 05 00 00 04 72 01 00 00 70 72 51 00 00 70 14 6f 53 00 00 06 38 00 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_SM_2147955418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.SM!MTB"
        threat_id = "2147955418"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 00 28 75 00 00 06 7e 04 00 00 04 7e 05 00 00 04 72 01 00 00 70 72 4d 00 00 70 14 6f 53 00 00 06 38 00 00 00 00 dd c7 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_AR_2147956204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.AR!MTB"
        threat_id = "2147956204"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 16 0c 2b ?? 06 08 8f 08 ?? ?? 01 25 71 08}  //weight: 5, accuracy: Low
        $x_25_2 = "C:\\Windows\\Media\\mppr.exe" ascii //weight: 25
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_GPV_2147958156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.GPV!MTB"
        threat_id = "2147958156"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 05 2b b5 16 0a 16 13 05 2b ae 04 03 61 1f 51 59 06 7e 16 00 00 04 20 d3 00 00 00 7e 16 00 00 04 20 d3 00 00 00 91 7e 16 00 00 04 20 8d 00 00 00 91 5f 1f 52 5f 9c 61 45 01 00 00 00 15 00 00 00 11 07 20 36 01 00 00 91 20 d2 00 00 00 59 13 05 38 63 ff ff ff 19 2b f6 14 0b 17 13 05}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_SLWC_2147958163_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.SLWC!MTB"
        threat_id = "2147958163"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 29 00 00 0a 6f 2a 00 00 0a 08 7e 2f 00 00 0a 6f 30 00 00 0a 07 14 16 8d 03 00 00 01 6f 31 00 00 0a 26}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Barys_NB_2147959749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Barys.NB!MTB"
        threat_id = "2147959749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Barys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 2e 00 00 0a 0c 72 6d 01 00 70 72 fb 00 00 70 28 2f 00 00 0a 28 30 00 00 0a 74 14 00 00 01 0d 09 72 29 01 00 70 6f 31 00 00 0a 09 72 33 01 00 70 6f 32 00 00 0a 09 20 10 27 00 00 6f 33 00 00 0a 09 20 10 27 00 00 6f 34 00 00 0a 09 16 6f 35 00 00 0a 28 36 00 00 0a 08 6f 37 00 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = {11 06 6f 3d 00 00 0a 73 3e 00 00 0a 6f 3f 00 00 0a 13 07 11 06 6f 40 00 00 0a 20 c8 00 00 00 2e 05 dd 83 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

