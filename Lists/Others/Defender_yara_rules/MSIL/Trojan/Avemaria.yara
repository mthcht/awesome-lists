rule Trojan_MSIL_Avemaria_ICYF_2147828534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Avemaria.ICYF!MTB"
        threat_id = "2147828534"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avemaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 08 a1 00 70 17 8d 17 00 00 01 25 16 07 a2 25 0c 14 14 17 8d 73 00 00 01 25 16 17 9c 25}  //weight: 1, accuracy: High
        $x_1_2 = "Buni555fu_Te5555xtB555ox" wide //weight: 1
        $x_1_3 = "GetMethod" ascii //weight: 1
        $x_1_4 = "ToString" ascii //weight: 1
        $x_1_5 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Avemaria_AMAB_2147852458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Avemaria.AMAB!MTB"
        threat_id = "2147852458"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avemaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 02 11 03 11 07 11 03 91 11 00 11 03 11 00 28 ?? ?? ?? 06 5d 28 ?? ?? ?? 06 61 d2 9c 20 ?? ?? ?? ?? 38 ?? ?? ?? ?? 11 03 11 07 8e 69}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Avemaria_KAB_2147892854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Avemaria.KAB!MTB"
        threat_id = "2147892854"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avemaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 02 06 02 06 91 20 ?? ?? 00 00 59 d2 9c 00 06 17 58 0a 06 02 8e 69 fe 04 0b 07 2d e3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Avemaria_KAC_2147895797_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Avemaria.KAC!MTB"
        threat_id = "2147895797"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avemaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 11 07 11 05 11 07 28 ?? 00 00 06 20 ?? ?? 00 00 61 d1 9d 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Avemaria_ABIX_2147896474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Avemaria.ABIX!MTB"
        threat_id = "2147896474"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avemaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 00 02 6f ?? ?? ?? 06 6f ?? ?? ?? 0a 00 02 6f ?? ?? ?? 06 6f ?? ?? ?? 0a 00 2a 35 00 72 ?? ?? ?? 70 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 06 6f}  //weight: 1, accuracy: Low
        $x_1_2 = "gagogaogoa.Resources" wide //weight: 1
        $x_1_3 = "cmd.exe taskkill /IM cmd.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Avemaria_KAD_2147899617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Avemaria.KAD!MTB"
        threat_id = "2147899617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Avemaria"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {00 03 1e 5d 10 01 03 16 fe 04 0a 06 2c 07 00 1e 03 58 10 01 00 02 03 1f 1f 5f 62 02 1e 03 59 1f 1f 5f 63 60 d2 0b 2b 00}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

