rule Trojan_MSIL_Blocker_NZV_2147837441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.NZV!MTB"
        threat_id = "2147837441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 06 16 73 ?? 00 00 0a 73 ?? 00 00 0a 0c 08 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d de}  //weight: 1, accuracy: Low
        $x_1_2 = "yQOhqoS0hy" wide //weight: 1
        $x_1_3 = "xHf3X8wmp.vP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_CAL_2147840786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.CAL!MTB"
        threat_id = "2147840786"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 08 16 16 02 74 ?? 00 00 1b 08 91 11 08 28 ?? 00 00 0a 18 28 ?? 00 00 06 28 ?? 00 00 0a 13 09 07 1a 9a 74 ?? 00 00 1b 08 11 09 28 ?? 00 00 0a 9c 08 17 d6 0c 00 08 8c ?? 00 00 01 07 19 9a 16 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 13 0a 11 0a 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_KAA_2147890143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.KAA!MTB"
        threat_id = "2147890143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {03 08 91 0d 08 18 5d 13 04 04 11 04 9a 13 05 03 08 02 11 05 09 28 ?? 00 00 06 9c 08 05 fe 01 13 06 11 06 2c 07 28 ?? 00 00 0a 0a 00 00 08 17 d6 0c 08 07 31 cb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_AAXY_2147897634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.AAXY!MTB"
        threat_id = "2147897634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {14 0a 00 73 ?? 00 00 0a 20 02 7e e1 e8 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 16 06 8e 69 28 ?? 00 00 0a 06 0b de 03 26 de d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_SPQC_2147901615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.SPQC!MTB"
        threat_id = "2147901615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {73 08 00 00 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 0d 09 28 ?? ?? ?? 2b 28 ?? ?? ?? 2b 0d dd 06 00 00 00 26 dd 00 00 00 00 09 2c d5}  //weight: 6, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_MBFV_2147903364_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.MBFV!MTB"
        threat_id = "2147903364"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 2f}  //weight: 1, accuracy: High
        $x_1_2 = {4c 00 2e 00 6f 00 2e 00 61 00 2e 00 64 00 2e 00 00 27}  //weight: 1, accuracy: High
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
        $x_1_4 = "CreateDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_SDF_2147905771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.SDF!MTB"
        threat_id = "2147905771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {61 11 06 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00 11 05 17 58 13 05}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_SPFM_2147911852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.SPFM!MTB"
        threat_id = "2147911852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 07 12 08 28 ?? ?? ?? 0a 11 05 11 04 11 06 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a dd 0f 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_SL_2147914439_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.SL!MTB"
        threat_id = "2147914439"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 09 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 18 58 0b 07 09 6f ?? ?? ?? 0a 32 dd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_SVPL_2147914980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.SVPL!MTB"
        threat_id = "2147914980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d1 13 0e 11 18 11 09 91 13 20 11 18 11 09 11 28 11 20 61 11 1c 19 58 61 11 30 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_SPZF_2147915071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.SPZF!MTB"
        threat_id = "2147915071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 16 11 19 11 09 91 13 28 11 19 11 09 11 28 11 20 61 19 11 18 58 61 11 32 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_SK_2147915519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.SK!MTB"
        threat_id = "2147915519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 09 07 18 6f ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 07 18 58 0b 07 09 6f ?? ?? ?? 0a 32 dd}  //weight: 2, accuracy: Low
        $x_2_2 = "Fractions.Exceptions.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_SM_2147922692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.SM!MTB"
        threat_id = "2147922692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 09 18 6f 88 01 00 0a 1f 10 28 1b 03 00 0a 13 04 11 04 16 32 08 08 11 04 6f 1c 03 00 0a 09 18 58 0d 09 07 6f 08 01 00 0a 32 d5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Blocker_SOZA_2147928389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Blocker.SOZA!MTB"
        threat_id = "2147928389"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blocker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 07 08 6f ?? 00 00 0a 06 6f ?? 00 00 0a 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d de 17 08 2c 06 08 6f ?? 00 00 0a dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

