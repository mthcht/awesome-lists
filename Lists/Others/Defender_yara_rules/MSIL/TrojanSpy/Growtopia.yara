rule TrojanSpy_MSIL_Growtopia_AGR_2147946484_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Growtopia.AGR!MTB"
        threat_id = "2147946484"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 16 1f 30 11 14 16 91 59 d2 13 17 00 11 14 13 20 16 13 21 2b 1b 11 20 11 21 91 13 22 11 15 11 17 11 22 58 d2 6f ?? 00 00 0a 00 11 21 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Growtopia_ARG_2147946540_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Growtopia.ARG!MTB"
        threat_id = "2147946540"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0d 2b 28 00 07 09 06 09 91 72 ?? 00 00 70 09 72 ?? 00 00 70 28 ?? 00 00 0a 5d 28 ?? 00 00 0a 61 d2 9c 00 09 13 04 11 04 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Growtopia_AWR_2147946541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Growtopia.AWR!MTB"
        threat_id = "2147946541"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 16 13 07 2b 1f 11 06 11 07 9a 28 ?? 00 00 0a 13 08 07 11 08 6f ?? 00 00 0a 6f ?? 00 00 0a 11 07 17 d6 13 07 11 07 11 06 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_MSIL_Growtopia_ARW_2147946542_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Growtopia.ARW!MTB"
        threat_id = "2147946542"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Growtopia"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 a2 25 18 72 ?? 03 00 70 a2 25 19 72 ?? 03 00 70 a2 25 1a 72 ?? 03 00 70 a2 25 1b 72 ?? 03 00 70 a2 25 1c 0e 06 a2 25 1d 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

