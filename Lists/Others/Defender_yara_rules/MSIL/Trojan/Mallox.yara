rule Trojan_MSIL_Mallox_NEAA_2147842567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mallox.NEAA!MTB"
        threat_id = "2147842567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 03 11 02 11 04 11 02 8e 69 5d 91 11 01 11 04 91 61 d2 6f ?? 00 00 0a}  //weight: 10, accuracy: Low
        $x_1_2 = "WindowsFormsApp" ascii //weight: 1
        $x_1_3 = "Stwxrnz" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mallox_SK_2147892527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mallox.SK!MTB"
        threat_id = "2147892527"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 72 01 00 00 70 6f 04 00 00 0a 6f 05 00 00 0a 6f 06 00 00 0a 6f 07 00 00 0a 6f 08 00 00 0a 0a dd 0d 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mallox_SL_2147899869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mallox.SL!MTB"
        threat_id = "2147899869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {d0 93 00 00 06 26 1f 0d 13 0e 2b a5 02 20 3f 9e dc 7c 61 03 61 0a 7e 59 00 00 04 0c 08 74 08 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 1f 0c 13 0e 38 7b ff ff ff}  //weight: 2, accuracy: High
        $x_2_2 = "rvaht.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mallox_SM_2147914437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mallox.SM!MTB"
        threat_id = "2147914437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 2d 1c 15 2c 19 08 07 09 18 6f 12 00 00 0a 1f 10 28 13 00 00 0a 6f 14 00 00 0a 09 18 58 0d 09 07 6f 15 00 00 0a 16 2d 1d 32 d5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Mallox_ND_2147915617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Mallox.ND!MTB"
        threat_id = "2147915617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Mallox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {19 91 6e 1d 2c 4c 1f 38 62 2b 5e 18 91 6e 1f 30 62 58 1d 2c 0c 2b 58 17 91 16 2d f1}  //weight: 5, accuracy: High
        $x_5_2 = {62 58 2b 46 1b 91 6e 19 2c 0c 1f 18 62 58 2b 3d 1a 91 1f 10 62 6a 58 2b 37 1d 91 18 2c f4 1e 62 6a 58 06 1c 91 6e 58}  //weight: 5, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "System.Net.Http" ascii //weight: 1
        $x_1_5 = "HttpClient" ascii //weight: 1
        $x_1_6 = "GetByteArrayAsync" ascii //weight: 1
        $x_1_7 = "DynamicInvoke" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

