rule Trojan_MSIL_Ader_SPQV_2147838119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.SPQV!MTB"
        threat_id = "2147838119"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_6_1 = {06 16 06 16 95 07 16 95 5a 20 f1 13 22 1d 58 9e 06 17 06 17 95 07 17 95 58 20 a7 a4 be 03 61 9e}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_CM_2147838316_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.CM!MTB"
        threat_id = "2147838316"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$d1cc2bad-d6f7-47b8-afa8-3a9d4430dcc1" ascii //weight: 1
        $x_1_2 = "Discord Link :  v1.0.0-custom" ascii //weight: 1
        $x_1_3 = "AnyDesk.exe" ascii //weight: 1
        $x_1_4 = "DownloadString" ascii //weight: 1
        $x_1_5 = "GetTempPath" ascii //weight: 1
        $x_1_6 = "DecodingBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_SPQ_2147840014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.SPQ!MTB"
        threat_id = "2147840014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LoginDaoComandos" ascii //weight: 1
        $x_1_2 = "Bemvindo_Load" ascii //weight: 1
        $x_1_3 = "Tela_Projet" ascii //weight: 1
        $x_1_4 = "Tela_Projet.DAL" ascii //weight: 1
        $x_1_5 = "Tela_Projet.MODELO" ascii //weight: 1
        $x_1_6 = "Erro com Banco de Dados!" wide //weight: 1
        $x_1_7 = "martinsrlk#7545" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_SPS_2147841205_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.SPS!MTB"
        threat_id = "2147841205"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 09 11 04 09 8e 69 5d 91 08 11 04 91 61 d2 6f ?? ?? ?? 0a 11 04 17 58 13 04 11 04 08 8e 69 32 df}  //weight: 4, accuracy: Low
        $x_1_2 = "80.66.75.135" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_PSID_2147843935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.PSID!MTB"
        threat_id = "2147843935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 05 00 00 70 28 ?? ?? ?? 0a 74 13 00 00 01 0a 06 6f ?? ?? ?? 0a 74 32 00 00 01 0b 73 ?? ?? ?? 0a 0c 00 07 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 80 03 00 00 04 00 de 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_EC_2147850521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.EC!MTB"
        threat_id = "2147850521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cnVuYXM=<IC1Db21tYW5kIEFkZC1NcFByZWZlcmVuY2UgLUV4Y2x1c2lvblBhdGggJw==" ascii //weight: 1
        $x_1_2 = "ZXhwbG9yZXIxLmV4ZQ==" ascii //weight: 1
        $x_1_3 = "QmlyIGhhdGEgb2x1xZ90dTog0U2VsZWN0ICogZnJvbSBXaW4zMl9Db21wdXRlclN5c3RlbQ==" ascii //weight: 1
        $x_1_4 = "VmlydHVhbEJveA==(U2VsZWN0ICogZnJvbSBXaW4zMl9EaXNrRHJpdmU=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_SZ_2147898860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.SZ!MTB"
        threat_id = "2147898860"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 02 08 6f 34 00 00 0a 0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 00 08 17 58 0c 08 07 8e 69 fe 04 13 07 11 07 2d cb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_PSDH_2147899355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.PSDH!MTB"
        threat_id = "2147899355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 04 6f 09 00 00 0a 0a 16 0b 2b 19 00 03 07 03 07 91 66 06 07 04 6f 0a 00 00 0a 5d 93 61 d2 9c 00 07 17 58 0b 07 03 8e 69 fe 04 0c 08 2d dd 03 0d 2b 00 09 2a}  //weight: 5, accuracy: High
        $x_1_2 = "ToArray" ascii //weight: 1
        $x_1_3 = "MemoryStream" ascii //weight: 1
        $x_1_4 = "Enumerable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_PSDY_2147899358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.PSDY!MTB"
        threat_id = "2147899358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 6f 37 00 00 0a 00 07 6f 35 ?? ?? ?? 16 6f 38 ?? ?? ?? 00 07 6f 39 ?? ?? ?? 26 07 6f 3a ?? ?? ?? 00 02 7b 12 00 00 04 25 6f 31 ?? ?? ?? 72 18 05 00 70 28 32 ?? ?? ?? 28 32 ?? ?? ?? 28 33 ?? ?? ?? 6f 30 ?? ?? ?? 00 00 02 7b 0d 00 00 04 6f 22 ?? ?? ?? 0c 08 2c 33 00 72 40 05 00 70 28 3b ?? ?? ?? 26 02 7b 12 00 00 04 25 6f 31 ?? ?? ?? 72 7c 05 00 70}  //weight: 5, accuracy: Low
        $x_1_2 = "DebuggingModes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_PSIC_2147899373_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.PSIC!MTB"
        threat_id = "2147899373"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 03 07 18 6f 16 00 00 0a 1f 10 28 17 00 00 0a 6f 18 00 00 0a 07 18 58 0b 07 03 6f 19 00 00 0a 32 de 06 6f 1a 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Ader_PSKP_2147899408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Ader.PSKP!MTB"
        threat_id = "2147899408"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 59 00 00 70 28 08 00 00 06 0a 28 1a 00 00 0a 06 6f 1b 00 00 0a 28 1c 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b de 03 26 de d4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

