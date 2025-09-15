rule Trojan_MSIL_VIPKeylogger_PLIRH_2147932157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.PLIRH!MTB"
        threat_id = "2147932157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 13 04 dd ?? 00 00 00 09}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_PHS_2147934617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.PHS!MTB"
        threat_id = "2147934617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 03 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_ZZQ_2147938294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.ZZQ!MTB"
        threat_id = "2147938294"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {08 11 07 8f ?? 00 00 01 25 47 09 11 07 58 1f 11 5a 20 00 01 00 00 5d d2 61 d2 52 09 1f 1f 5a 08 11 07 91 58 20 00 01 00 00 5d 0d 11 07 17 58 13 07}  //weight: 6, accuracy: Low
        $x_5_2 = {08 11 06 11 06 1f 25 5a 20 00 01 00 00 5d d2 9c 11 06 17 58 13 06 11 06 08 8e 69 32 e3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_ARQA_2147938525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.ARQA!MTB"
        threat_id = "2147938525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 74 04 00 00 1b 09 07 75 04 00 00 1b 09 94 02 5a 1f 64 5d 9e 11}  //weight: 3, accuracy: High
        $x_3_2 = {1b 11 04 07 ?? 04 00 00 1b 11 04 94 03 5a 1f 64 5d 9e}  //weight: 3, accuracy: Low
        $x_2_3 = {11 07 16 28 ?? 00 00 06 13 0c 11 07 17 28 ?? 00 00 06 13 0d 11 07 18 28 ?? 00 00 06 13 0e}  //weight: 2, accuracy: Low
        $x_2_4 = {03 11 0c 6f ?? 00 00 0a 03 11 0d 6f ?? 00 00 0a 03 11 0e 6f ?? 00 00 0a 06 19 58 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_SXDA_2147939358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.SXDA!MTB"
        threat_id = "2147939358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 37 2b 3c 72 ?? ?? ?? 70 2b 3c 1e 2c 1a 2b 3e 72 ?? ?? ?? 70 2b 3a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0a 07 6f ?? ?? ?? 0a 06 0c de 37 73 ?? ?? ?? 0a 2b c9 0b 2b c8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_ZZV_2147941824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.ZZV!MTB"
        threat_id = "2147941824"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 59 03 6f ?? 01 00 0a 6f ?? 01 00 0a 20 00 01 00 00 5d 03 6f ?? 01 00 0a 6f ?? 01 00 0a 20 00 01 00 00 5d 61 d2 03 6f ?? 01 00 0a 6f ?? 01 00 0a 1f 1f 5a 03 6f ?? 01 00 0a 6f ?? 01 00 0a 58 20 ff 00 00 00 5f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_ACH_2147943978_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.ACH!MTB"
        threat_id = "2147943978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 05 0e 04 6f ?? 00 00 0a 0a 06 0e 05 28 ?? 00 00 06 0b 04 03 6f ?? 00 00 0a 59 0c 08 19 32 0a 03 07 0e 05 28 ?? 00 00 06 2a 08 16 31 0a 03 07 08 0e 05 28}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_ACH_2147943978_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.ACH!MTB"
        threat_id = "2147943978"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {6c 5b 13 0d 02 11 15 11 17 6f ?? 00 00 0a 13 18 12 18 28 ?? 00 00 0a 16 32 19 12 18 28 ?? 00 00 0a 16 32 0f 12 18 28 ?? 00 00 0a 16 fe 04 16 fe 01 2b 01 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_AFXA_2147944321_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.AFXA!MTB"
        threat_id = "2147944321"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 06 07 6f ?? 00 00 0a 0c 04 03 6f ?? 00 00 0a 59 0d 09 19 fe 04 16 fe 01 13 04 11 04 2c 2e 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 02 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 56 09 16 fe 02 13 05 11 05 2c 4c 00 19 8d ?? 00 00 01 25 16 12 02 28 ?? 00 00 0a 9c 25 17 12 02 28 ?? 00 00 0a 9c 25 18 12 02 28 ?? 00 00 0a 9c}  //weight: 5, accuracy: Low
        $x_2_2 = {13 06 16 13 07 2b 14 00 03 11 06 11 07 91 6f ?? 00 00 0a 00 00 11 07 17 58 13 07 11 07 09 fe 04 13 08 11 08 2d e1}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_ZKS_2147944620_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.ZKS!MTB"
        threat_id = "2147944620"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 11 20 58 13 33 02 11 31 11 35 6f ?? 00 00 0a 13 38 12 38 28 ?? 00 00 0a 06 61 d2 13 39 12 38 28 ?? 00 00 0a 06 61 d2 13 3a 12 38 28 ?? 00 00 0a 06 61 d2 13 3b 11 39 07 1f 1f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_ZSR_2147946558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.ZSR!MTB"
        threat_id = "2147946558"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 09 06 6f ?? 02 00 0a 6f ?? 02 00 0a 00 11 09 06 6f ?? 02 00 0a 6f ?? 02 00 0a 00 7e ?? 01 00 04 2c 07 7e ?? 01 00 04 2b 16 7e ?? 01 00 04 fe ?? 48 01 00 06 73 ?? 02 00 0a 25 80 ?? 01 00 04 13 0a 00 11 09 6f ?? 02 00 0a 13 0b 02 11 0a 07 6f ?? 02 00 0a 11 0b 6f ?? 02 00 0a 6f ?? 01 00 0a 00 de 0e}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_PGV_2147947446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.PGV!MTB"
        threat_id = "2147947446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5a 13 12 12 06 28 ?? 00 00 0a 0e 04 7b 20 00 00 04 06 0e 04 7b 20 00 00 04 8e 69 5d 91 61 d2 13 13 12 06 28 ?? 00 00 0a 0e 04 7b 20 00 00 04 11 05 0e 04 7b 20 00 00 04 8e 69 5d 91 61 d2 13 14 12 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_AMBB_2147948259_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.AMBB!MTB"
        threat_id = "2147948259"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 0a 06 02 7d ?? 00 00 04 06 03 7d ?? 00 00 04 16 02 7b ?? 00 00 04 6f ?? 01 00 0a 28 ?? 01 00 0a 02 7b ?? 00 00 04 25 2d 16 26 02 02 fe ?? ?? 01 00 06 73 ?? 01 00 0a 25 0b 7d ?? 00 00 04 07 28 ?? 00 00 2b 06 fe ?? ?? 01 00 06 73 ?? 01 00 0a 28 ?? 00 00 2b 2a}  //weight: 5, accuracy: Low
        $x_2_2 = {0a 59 0a 06 19 fe 04 16 fe 01 0b 07 2c 34 00 02 7b ?? 00 00 04 19 8d ?? 00 00 01 25 16 0f 01 28 ?? 01 00 0a 9c 25 17 0f 01 28 ?? 01 00 0a 9c 25 18 0f 01 28 ?? 01 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_RVA_2147951324_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.RVA!MTB"
        threat_id = "2147951324"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 9d a2 29 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 9e 00 00 00 0e 00 00 00 4d 00 00 00 b2 01 00 00 61 00 00 00 1e 01 00 00 11 00 00 00 38 00 00 00 01 00 00 00 2d 00 00 00 05 00 00 00 10 00 00 00 1c 00 00 00 06 00 00 00 01 00 00 00 01 00 00 00 07 00 00 00 03 00 00 00 01 00 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = "12345678-1234-1234-1234-123456789012" ascii //weight: 1
        $x_1_3 = "CSVViewer.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_VIPKeylogger_RVB_2147952235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/VIPKeylogger.RVB!MTB"
        threat_id = "2147952235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "VIPKeylogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {57 1d a2 0b 09 0b 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 7f 00 00 00 0c 00 00 00 62 00 00 00 73 00 00 00 55 00 00 00 d9 00 00 00 05 00 00 00 48 00 00 00 29 00 00 00 03 00 00 00 12 00 00 00 20 00 00 00 01 00 00 00 06 00 00 00 01 00 00 00 08 00 00 00 06 00 00 00 01 00 00 00 03}  //weight: 1, accuracy: High
        $x_1_2 = "ecacec1c-da19-4421-9867-15e216f473fd" ascii //weight: 1
        $x_1_3 = "BaselineTool.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

