rule Trojan_MSIL_ArkeiStealer_CN_2147843363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.CN!MTB"
        threat_id = "2147843363"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 02 7b 71 00 00 04 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 58 7d ?? ?? ?? ?? 00 02 7b ?? ?? ?? ?? 0c 02 08 17 58 7d ?? ?? ?? ?? 02 7b ?? ?? ?? ?? 02 7b ?? ?? ?? ?? 1d 1f 0e 6f 6f 01 00 0a fe 04}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArkeiStealer_ABYZ_2147848761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.ABYZ!MTB"
        threat_id = "2147848761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 8e 69 28 ?? 00 00 06 0d 19 00 06 28 ?? 00 00 06 7e ?? 00 00 04 16 7e}  //weight: 2, accuracy: Low
        $x_1_2 = {49 00 6d 00 61 00 67 00 65 00 52 00 65 00 73 00 69 00 7a 00 69 00 6e 00 67 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 1, accuracy: High
        $x_1_3 = "DataBasePracticalJob" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArkeiStealer_ABZG_2147848763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.ABZG!MTB"
        threat_id = "2147848763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {04 8e 69 28 ?? 00 00 06 13 03 1b 00 11 04 6f ?? 00 00 0a 7e ?? 00 00 04 16 7e}  //weight: 2, accuracy: Low
        $x_1_2 = "DataBasePracticalJob" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArkeiStealer_ABZX_2147849002_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.ABZX!MTB"
        threat_id = "2147849002"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {41 00 75 00 74 00 6f 00 49 00 74 00 4f 00 53 00 44 00 42 00 61 00 63 00 6b 00 67 00 72 00 6f 00 75 00 6e 00 64 00 2e 00 50 00 72 00 6f 00 70 00 65 00 72 00 74 00 69 00 65 00 73 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73}  //weight: 2, accuracy: High
        $x_1_2 = "4dda05b6-c125-4b6f-9b38-5ca666b517c8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArkeiStealer_ABZS_2147849178_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.ABZS!MTB"
        threat_id = "2147849178"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 02 16 03 8e 69 28 ?? 00 00 06 13 15 00 7e ?? 00 00 04 28}  //weight: 2, accuracy: Low
        $x_1_2 = {44 00 61 00 74 00 61 00 42 00 61 00 73 00 65 00 50 00 72 00 61 00 63 00 74 00 69 00 63 00 61 00 6c 00 4a 00 6f 00 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArkeiStealer_AAHL_2147851702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.AAHL!MTB"
        threat_id = "2147851702"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 25 17 28 ?? 00 00 06 25 18 6f ?? 00 00 0a 25 11 00 6f ?? 00 00 0a 6f ?? 00 00 0a 11 01 16 11 01 8e 69 28 ?? 00 00 06 13 03}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArkeiStealer_AAHM_2147851703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.AAHM!MTB"
        threat_id = "2147851703"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 25 08 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 25 06 6f ?? 00 00 0a 6f ?? 00 00 0a 07 16 07 8e 69 6f ?? 00 00 0a 0d}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArkeiStealer_AAQL_2147891966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.AAQL!MTB"
        threat_id = "2147891966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 06 1b 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d 17 2c e8 09 03 16 03 8e 69 6f ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArkeiStealer_AATB_2147893241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.AATB!MTB"
        threat_id = "2147893241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {04 06 18 28 ?? 01 00 06 7e ?? 00 00 04 06 1b 28 ?? 01 00 06 7e ?? 00 00 04 06 28 ?? 01 00 06 0d 7e ?? 00 00 04 09 05 16 05 8e 69 28 ?? 01 00 06 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_ArkeiStealer_AAZO_2147898895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/ArkeiStealer.AAZO!MTB"
        threat_id = "2147898895"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArkeiStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 1f 20 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 1f 10 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 20 10 7e 02 00 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 73 ?? 00 00 0a 13 05 11 04 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 0c de 22 11 05 2c 07 11 05 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

