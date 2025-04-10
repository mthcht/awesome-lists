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

