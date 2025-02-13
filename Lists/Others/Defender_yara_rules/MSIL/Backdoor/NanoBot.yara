rule Backdoor_MSIL_NanoBot_B_2147755696_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoBot.B!MTB"
        threat_id = "2147755696"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 00 02 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 28 ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 0b 07 6f ?? ?? ?? ?? 17 9a 0c 02 08 28 ?? ?? ?? ?? 00 28 ?? ?? ?? ?? 00 16 0d 2b 00 09}  //weight: 1, accuracy: Low
        $x_1_2 = "get_Encrypted2" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "Yoda-Coffee3" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NanoBot_D_2147755697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoBot.D!MTB"
        threat_id = "2147755697"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 00 02 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 28 ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 0b 07 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 0c 02 08 28 ?? ?? ?? ?? 00 28 ?? ?? ?? ?? 00 16 0d}  //weight: 10, accuracy: Low
        $x_1_2 = "_PROFILER" wide //weight: 1
        $x_1_3 = "_ENABLE_PROFILING" wide //weight: 1
        $x_1_4 = "dnspyA" ascii //weight: 1
        $x_1_5 = "newworldorder" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_NanoBot_PA_2147765607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoBot.PA!MTB"
        threat_id = "2147765607"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "DONT_MUTATE" wide //weight: 1
        $x_1_2 = {8e 69 17 da 17 d8 13 ?? 16 13 ?? 2b}  //weight: 1, accuracy: Low
        $x_1_3 = {8e 69 5d 91 09 11 ?? 09 8e 69 5d 91 61 [0-16] 17 d6 [0-8] 8e 69 5d 91 da 20 [0-8] d6 20 [0-8] 5d b4 9c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NanoBot_AN_2147822815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoBot.AN!MTB"
        threat_id = "2147822815"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 1f 00 00 70 28 01 00 00 06 00 2a}  //weight: 2, accuracy: High
        $x_2_2 = {07 16 6f 05 ?? ?? 0a 00 07 17 6f 06 ?? ?? 0a 1c 00 73 03 ?? ?? 0a 0a 06 73 04 ?? ?? 0a 0b}  //weight: 2, accuracy: Low
        $x_1_3 = "ExecuteCommandAsAdmin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NanoBot_SK_2147851081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoBot.SK!MTB"
        threat_id = "2147851081"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 11 04 07 11 04 18 5a 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a d2 9c 00 11 04 17 58 13 04 11 04 08 8e 69 fe 04 13 05 11 05 2d d4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_NanoBot_SM_2147917842_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/NanoBot.SM!MTB"
        threat_id = "2147917842"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NanoBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {19 2c 0d 2b 0d 72 a5 00 00 70 2b 0d 2b 12 2b 17 de 1b 73 55 00 00 0a 2b ec 28 56 00 00 0a 2b ec 6f 57 00 00 0a 2b e7 0a 2b e6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

