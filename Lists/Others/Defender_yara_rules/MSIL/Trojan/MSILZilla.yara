rule Trojan_MSIL_MSILZilla_RDA_2147838981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILZilla.RDA!MTB"
        threat_id = "2147838981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7dffb864-cef4-4393-a913-af0d138dedab" ascii //weight: 1
        $x_1_2 = "Asgard-Crack" ascii //weight: 1
        $x_1_3 = "{r9eny5jr-kw4z-yhsk-90cc-b7667zmlsw1u}" ascii //weight: 1
        $x_1_4 = "127.0.0.1 a086e0efbad65f0bb.awsglobalaccelerator.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MSILZilla_RDC_2147841239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILZilla.RDC!MTB"
        threat_id = "2147841239"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "6767DCD6-E93A-4A49-9AED-AA134D2CAC9C" ascii //weight: 1
        $x_1_2 = "inetinfo" ascii //weight: 1
        $x_1_3 = "buOeP1vJCfhdRTKRPv.EYAmPYb2sXkUxkom58" ascii //weight: 1
        $x_1_4 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MSILZilla_CXI_2147842131_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILZilla.CXI!MTB"
        threat_id = "2147842131"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 18 5b 06 09 18 6f ?? ?? ?? ?? 1f 10 28 1c ?? ?? ?? 9c 09 18 58 0d 09 07 32}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MSILZilla_PSPM_2147848882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILZilla.PSPM!MTB"
        threat_id = "2147848882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 07 00 00 0a 07 6f 08 00 00 0a 08 6f 07 00 00 0a 16 6f 09 00 00 0a 08 6f 07 00 00 0a 17 6f 0a 00 00 0a 08 6f 0b 00 00 0a 26 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MSILZilla_CCHZ_2147907446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILZilla.CCHZ!MTB"
        threat_id = "2147907446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0a 11 0c 18 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 11 0c 18 58 13 0c 11 0c 11 0b 31 ca}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MSILZilla_NITA_2147926332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILZilla.NITA!MTB"
        threat_id = "2147926332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "bypassing login" wide //weight: 2
        $x_2_2 = "possible breach detected" wide //weight: 2
        $x_2_3 = "Possible malicious activity detected" wide //weight: 2
        $x_1_4 = "MaliciousCheck" ascii //weight: 1
        $x_1_5 = "DNS redirecting has been detected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MSILZilla_GKN_2147931265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILZilla.GKN!MTB"
        threat_id = "2147931265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 03 00 3b 30 00 00 00 fe 0c 09 00 fe 0c 05 00 46 fe 0c 13 00 61 52 fe 0c 05 00 20 01 00 00 00 58 fe 0e 05 00 fe 0c 09 00 20 01 00 00 00 58 fe 0e 09 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MSILZilla_AKS_2147953339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MSILZilla.AKS!MTB"
        threat_id = "2147953339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MSILZilla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {07 72 ad 00 00 70 6f 03 00 00 0a 0a dd 0d 00 00 00}  //weight: 3, accuracy: High
        $x_2_2 = {03 28 0f 00 00 0a 6f 10 00 00 0a 0a 16 0b 38 41 00 00 00 06 07 a3 0d 00 00 01 0c 08 6f 11 00 00 0a 04 28 12 00 00 0a 39 24 00 00 00 08 05 1f 38 6f 13 00 00 0a 0d 09 14 28 14 00 00 0a 39 09 00 00 00 09 14 14 6f 15 00 00 0a 26 dd 15 00 00 00 07 17 58 0b 07 06 8e 69 32 b9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

