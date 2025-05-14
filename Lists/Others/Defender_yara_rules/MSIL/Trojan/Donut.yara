rule Trojan_MSIL_Donut_NEAA_2147836651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Donut.NEAA!MTB"
        threat_id = "2147836651"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 03 2d 18 07 06 28 1d 00 00 0a 72 ?? 09 00 70 6f 1e 00 00 0a 6f 23 00 00 0a 2b 16 07 06 28 1d 00 00 0a 72 ?? 09 00 70 6f 1e 00 00 0a 6f 24 00 00 0a 17 73 25 00 00 0a 0d 09 02 16 02 8e 69}  //weight: 10, accuracy: Low
        $x_2_2 = "set_WindowStyle" ascii //weight: 2
        $x_2_3 = "Select CommandLine, ProcessID from Win32_Process" wide //weight: 2
        $x_2_4 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Donut_GAU_2147848262_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Donut.GAU!MTB"
        threat_id = "2147848262"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 16 0c 2b 1d 00 06 07 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 08 17 58 0c 08 07 6f ?? 00 00 0a fe 04 13 04 11 04 2d d4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Donut_KA_2147849323_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Donut.KA!MTB"
        threat_id = "2147849323"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 06 08 18 73 ?? 00 00 0a 0d 07 09 ?? ?? ?? ?? ?? 28 0a 00 00 0a 6f ?? 00 00 0a 00 00 08 18 58 0c 08 06 8e 69 fe 04 13 05 11 05 2d d3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Donut_AAEQ_2147850707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Donut.AAEQ!MTB"
        threat_id = "2147850707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {69 17 59 2b 3b 2b 2e 2b 3a 50 2b 3a 91 16 2c 39 26 2b 39 50 2b 39 2b 3a 50 07 91 9c 02 50 07 08 9c 06 16 2d d2 17 25 2c 0e 58 17 2c 02 0a 07 15 2c db 17 59 0b 06 07 32 ce 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Donut_FNAA_2147903377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Donut.FNAA!MTB"
        threat_id = "2147903377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {02 8e 69 8d 0f 00 00 01 0a 16 0b 2b 13 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 02 8e 69 32 e7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Donut_KAB_2147910955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Donut.KAB!MTB"
        threat_id = "2147910955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 61 0b 07 20 ?? ?? ?? ?? 61 07 20 ?? ?? ?? ?? 62 0b 59 0a 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Donut_KAC_2147913640_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Donut.KAC!MTB"
        threat_id = "2147913640"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 08 02 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 04 11 04 2d df}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Donut_UJAA_2147919390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Donut.UJAA!MTB"
        threat_id = "2147919390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a dd}  //weight: 4, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Donut_MKV_2147941401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Donut.MKV!MTB"
        threat_id = "2147941401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Donut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 06 08 20 e8 03 00 00 73 3f 00 00 0a 13 05 00 11 05 1f 20 6f ?? 00 00 0a 13 06 73 41 00 00 0a 13 07 00 11 07 20 00 01 00 00 6f ?? 00 00 0a 00 11 07 17 6f ?? 00 00 0a 00 11 07 18 6f ?? 00 00 0a 00 11 07 11 06 09 6f ?? 00 00 0a 13 08 00 11 04 73 52 00 00 0a 13 09 00 11 09 11 08 16 73 47 00 00 0a 13 0a 11 0a 28 ?? 00 00 0a 73 53 00 00 0a 13 0b 00 11 0b 6f ?? 00 00 0a 13 0c de 4e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

