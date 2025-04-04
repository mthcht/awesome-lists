rule Trojan_MSIL_Strictor_PSOS_2147847839_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.PSOS!MTB"
        threat_id = "2147847839"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 39 00 00 0a 03 6f 3a 00 00 0a 0a 06 28 3b 00 00 0a 0b 07 0c 2b 00 08 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_KAA_2147896403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.KAA!MTB"
        threat_id = "2147896403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {69 5d 91 08 09 08 6f ?? 01 00 0a 5d 6f ?? 01 00 0a 61 28 ?? 01 00 0a 07 09 17 58 07 8e 69 5d 91}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_SK_2147898757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.SK!MTB"
        threat_id = "2147898757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {20 00 01 00 00 13 05 06 08 5d 13 06 06 17 58 08 5d 13 0b 07 11 0b 91 11 05 58 13 0c 07 11 06 91 13 0d 11 0d 11 07 06 1f 16 5d 91 61 13 0e 11 0e 11 0c 59 13 0f 07 11 06 11 0f 11 05 5d d2 9c 06 17 58 0a 06 08 11 08 17 58 5a fe 04 13 10 11 10 2d ae}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_MBFV_2147902999_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.MBFV!MTB"
        threat_id = "2147902999"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 08 06 07 06 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 11 08 61 13 09 06 11 06 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_NA_2147904507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.NA!MTB"
        threat_id = "2147904507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 2a 61 19 11 1f 58 61 11 2e 61 d2}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_PAQ_2147917929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.PAQ!MTB"
        threat_id = "2147917929"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {20 65 62 3d bf 65 20 01 a9 71 13 61 7e 9f 00 00 04 7b 72 00 00 04 61 28 ?? ?? ?? 06 11 03 73 25 00 00 0a 13 02 20 00 00 00 00 7e 9f 00 00 04 7b 8a 00 00 04}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_GP_2147925157_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.GP!MTB"
        threat_id = "2147925157"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "killMC" ascii //weight: 2
        $x_2_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 2
        $x_1_3 = "FlashSettings.txt" ascii //weight: 1
        $x_4_4 = "Minecraft Stealer" ascii //weight: 4
        $x_1_5 = "servers.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_ARS_2147926091_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.ARS!MTB"
        threat_id = "2147926091"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 19 2f 02 2b 54 0f 01 28 ?? 00 00 0a 1f 10 62 0f 01 28 ?? 00 00 0a 1e 62 60 0f 01 28 ?? 00 00 0a 60 0a 19 8d ?? 00 00 01 25 16 06 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 06 1e 63}  //weight: 2, accuracy: Low
        $x_1_2 = {02 04 05 28 ?? 00 00 06 0a 0e 04 03 6f ?? 00 00 0a 59 0b 03 06 07 28 ?? 00 00 06 00 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_AMCZ_2147930714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.AMCZ!MTB"
        threat_id = "2147930714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {28 1d 00 00 0a 72 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 28 1d 00 00 0a 72 ?? 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 2a}  //weight: 4, accuracy: Low
        $x_1_2 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 00 53 74 72 69 6e 67 00 43 6f 6e 63 61 74 00 50 72 6f 63 65 73 73 00 53 74 61 72 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Strictor_PA_2147937896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Strictor.PA!MTB"
        threat_id = "2147937896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Strictor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 17 58 28 6a 00 00 06 28 43 00 00 0a 5d 13 05 11 06 09 11 05 94 58 28 6b 00 00 06 28 43 00 00 0a 5d 13 06 09 11 05 94 13 0d 09 11 05 09 11 06 94 9e 09 11 06 11 0d 9e 09 09 11 05 94 09 11 06 94 58 20 00 01 00 00 5d 94 13 0e 11 07 11 0c 02 11 0c 91 11 0e 61 28 44 00 00 0a 9c 11 0c 17 58 13 0c 11 0c 02 8e 69 32 96}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

