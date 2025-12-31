rule Trojan_MSIL_Snakelogger_SK_2147898090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakelogger.SK!MTB"
        threat_id = "2147898090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 07 28 63 00 00 0a 16 fe 01 13 09 11 09 2c 0e 00 11 06 11 07 28 ?? ?? ?? 0a 00 00 2b 06 00 08 17 58 0c 00 00 2b 10 00 02 7b 14 00 00 04 11 06 6f ?? ?? ?? 0a 00 00 00 11 05 17 58 13 05 11 05 03 fe 04 13 0a 11 0a 3a 56 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakelogger_SL_2147900946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakelogger.SL!MTB"
        threat_id = "2147900946"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 7e 09 00 00 04 07 17 8d 21 00 00 01 25 16 02 a2 6f 4e 00 00 0a 26 00 de 05}  //weight: 2, accuracy: High
        $x_2_2 = "SupervisorWebService.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakelogger_AMMB_2147904610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakelogger.AMMB!MTB"
        threat_id = "2147904610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d d4 91 28 ?? ?? 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? 00 0a 9c 09 17 6a 58}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakelogger_KAC_2147912718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakelogger.KAC!MTB"
        threat_id = "2147912718"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 19 00 06 07 7e ?? 00 00 04 07 91 02 07 02 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe 04 0c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakelogger_KAE_2147913246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakelogger.KAE!MTB"
        threat_id = "2147913246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 19 00 06 07 7e ?? 00 00 04 07 91 03 07 02 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 7e ?? 00 00 04 8e 69 fe 04 0c 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakelogger_KAF_2147913351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakelogger.KAF!MTB"
        threat_id = "2147913351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 19 00 02 06 7e ?? 00 00 04 06 91 03 06 04 8e 69 5d 91 61 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakelogger_KAD_2147920815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakelogger.KAD!MTB"
        threat_id = "2147920815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "BlackHawk\\User Data\\Default\\Login Data" ascii //weight: 5
        $x_1_2 = "SnakeKeylogger" ascii //weight: 1
        $x_1_3 = "software\\microsoft\\windows\\currentversion\\run" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakelogger_PKUH_2147928393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakelogger.PKUH!MTB"
        threat_id = "2147928393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 06 03 04 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0b de 13}  //weight: 8, accuracy: Low
        $x_2_2 = "CreateDecryptor" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Snakelogger_PS_2147960304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Snakelogger.PS!MTB"
        threat_id = "2147960304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Snakelogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 02 03 04 06 07 05 0e 04 0e 05 23 ?? ?? ?? ?? ?? ?? ?? ?? 28 ?? ?? ?? 06 00 00 06 17 58 0a 06 02 6f ?? ?? ?? 0a 2f 0b 03 6f ?? ?? ?? 0a 04 fe 04 2b 01 16 0c 08}  //weight: 10, accuracy: Low
        $x_1_2 = "txtDoktorRePassword" ascii //weight: 1
        $x_1_3 = "PharmacyProject.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

