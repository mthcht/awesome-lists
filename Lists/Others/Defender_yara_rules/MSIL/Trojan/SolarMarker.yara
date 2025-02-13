rule Trojan_MSIL_SolarMarker_AD_2147787060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SolarMarker.AD!MTB"
        threat_id = "2147787060"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolarMarker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Roaming\\solarmarker.dat" ascii //weight: 1
        $x_1_2 = "93e69b15-f4db-4aca-9738-e3bbdce3fec1.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_SolarMarker_ZZ_2147793456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SolarMarker.ZZ"
        threat_id = "2147793456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolarMarker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 1f 68 9d 11 ?? 17 1f 77 9d 11 ?? 18 1f 69 9d 11 ?? 19 1f 64 9d}  //weight: 5, accuracy: Low
        $x_5_2 = {16 1f 64 9d 11 ?? 17 1f 6e 9d 11 ?? 18 1f 73 9d 11}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SolarMarker_NYH_2147828198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SolarMarker.NYH!MTB"
        threat_id = "2147828198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolarMarker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 11 09 94 9e 11 07 11 09 11 0a 9e 11 07 11 07 11 08 94 11 07 11 09 94 58 07 5d 94 13 0d 11 0b 11 0c 02 11 0c 91 11 0d 61 d2 9c 00 11 0c 17 58 13 0c}  //weight: 1, accuracy: High
        $x_1_2 = "$44260b1a-2fd0-448a-abb4-54a7829ab6d4" ascii //weight: 1
        $x_1_3 = {57 dd 02 28 09 0e 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 17 05 00 00 1d 00 00 00 1a 00 00 00 42 02 00 00 53 00 00 00 6b 07 00 00 05 00 00 00 24 00 00 00 01 00 00 00 01 00 00 00 c1 00 00 00 51}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SolarMarker_AVN_2147887402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SolarMarker.AVN!MTB"
        threat_id = "2147887402"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolarMarker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 13 0c 2b 53 00 11 08 17 58 07 5d 13 08 11 09 11 07 11 08 94 58 07 5d 13 09 11 07 11 08 94 13 0a 11 07 11 08 11 07 11 09 94 9e 11 07 11 09 11 0a 9e 11 07 11 07 11 08 94 11 07 11 09 94 58 07 5d 94 13 0d 11 0b 11 0c 02 11 0c 91 11 0d 61 d2 9c 00 11 0c 17 58 13 0c 11 0c 02 8e 69 fe 04 13 0f 11 0f 2d a0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SolarMarker_AG_2147891588_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SolarMarker.AG!MTB"
        threat_id = "2147891588"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolarMarker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0d 16 13 04 2b 17 09 11 04 08 17 20 ?? 00 00 00 6f ?? 00 00 0a d2 9c 11 04 17 58 13 04 11 04 09 8e 69 17 59 fe 04 13 10 11 10 2d da}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SolarMarker_AS_2147893462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SolarMarker.AS!MTB"
        threat_id = "2147893462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolarMarker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 07 6f ?? 00 00 0a 00 03 7b ?? 00 00 04 8e 69 06 8e 69 58 8d ?? 00 00 01 0c 16 0d 2b 3a 00 09 03 7b ?? 00 00 04 8e 69 fe 04 16 fe 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SolarMarker_ASM_2147894352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SolarMarker.ASM!MTB"
        threat_id = "2147894352"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolarMarker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0c 2b 3a 00 08 03 7b ?? ?? ?? 04 8e 69 fe 04 16 fe 01 13 08 11 08 2d 0f 00 07 08 03 7b ?? ?? ?? 04 08 91 9c 00 2b 11 00 07 08 06 08 03 7b ?? ?? ?? 04 8e 69 59 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SolarMarker_MA_2147896792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SolarMarker.MA!MTB"
        threat_id = "2147896792"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SolarMarker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "JHA9J3N1bXBkZi1pbnN0YWxsZXIteDY0LWJ1bmRsZS5leGUnOyhOZXctT2JqZWN0IFN5c3RlbS5OZXQuV2ViQ2xpZW50KS5Eb3dubG9hZE" wide //weight: 3
        $x_1_2 = "INCORRECT_PASSWORD" ascii //weight: 1
        $x_1_3 = "USERNAME_TARGET_CREDENTIALS" ascii //weight: 1
        $x_1_4 = "CreateRunspace" ascii //weight: 1
        $x_1_5 = "PromptForPassword" ascii //weight: 1
        $x_1_6 = "CredUIPromptForCredentials" ascii //weight: 1
        $x_1_7 = "NotifyEndApplication" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

