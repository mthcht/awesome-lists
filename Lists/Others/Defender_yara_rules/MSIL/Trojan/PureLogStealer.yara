rule Trojan_MSIL_PureLogStealer_AFAA_2147900222_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AFAA!MTB"
        threat_id = "2147900222"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 91 61 28 ?? ?? 00 06 ?? 08 20 87 10 00 00 58 20 86 10 00 00 59 ?? 8e 69 5d 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_BVAA_2147901272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.BVAA!MTB"
        threat_id = "2147901272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 17 58 0b 1c 2c ?? 07 1b 32 ?? 2a 0a 38 ?? ff ff ff 28 ?? 00 00 06 38 ?? ff ff ff 0a 38 ?? ff ff ff 0b 38 ?? ff ff ff 06 38 ?? ff ff ff 28 ?? 00 00 2b 38 ?? ff ff ff 28 ?? 00 00 2b 38 ?? ff ff ff 28 ?? 00 00 0a 38 ?? ff ff ff 02 38}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_APL_2147902197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.APL!MTB"
        threat_id = "2147902197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 04 17 13 05 38 ?? 00 00 00 11 04 11 05 58 13 04 11 05 17 58 13 05 11 05 02 31 ee 07 6f ?? 00 00 0a 28 ?? 00 00 2b 13 06 11 04 28 ?? 00 00 0a 11 04 1f 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_DMAA_2147902381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.DMAA!MTB"
        threat_id = "2147902381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 07 17 6f ?? 00 00 0a 73 ?? 00 00 0a 13 0c 11 0c 11 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {13 0e 11 0d 11 0e 16 11 0e 8e 69 6f ?? 00 00 0a 28 ?? 00 00 0a 11 0c 6f ?? 00 00 0a 6f ?? 00 00 0a 0c de 24}  //weight: 2, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_DPAA_2147902407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.DPAA!MTB"
        threat_id = "2147902407"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 06 58 0d 06 17 58 0a 06 02 31 f4}  //weight: 2, accuracy: High
        $x_2_2 = {20 00 01 00 00 14 14 14 6f ?? ?? 00 0a 26 11 04 07 5a 13 04 07 17 58 0b 07 02 31 d8}  //weight: 2, accuracy: Low
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_DQAA_2147902424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.DQAA!MTB"
        threat_id = "2147902424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {09 d3 07 58 11 04 d3 06 58 47 52 08 16 fe 01 13 0d 11 0d 2d 23 00 09 d3 07 58 09 d3 07 58 47 1a 63 d2 52 09 d3 07 58 25 47 11 04 d3 06 17 58 58 47 1a 62 d2 58 d2 52}  //weight: 4, accuracy: High
        $x_1_2 = "VmLoad" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_DTAA_2147902495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.DTAA!MTB"
        threat_id = "2147902495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 58 0c 09 17 58 0d 09 02 31 f4}  //weight: 2, accuracy: High
        $x_2_2 = {11 04 11 05 5a 13 04 11 05 17 58 13 05 11 05 02 31 ee}  //weight: 2, accuracy: High
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_DUAA_2147902594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.DUAA!MTB"
        threat_id = "2147902594"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 11 02 58 13 01 20 07 00 00 00 7e ?? 00 00 04 7b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AMAG_2147902846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AMAG!MTB"
        threat_id = "2147902846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 20 ff 00 00 00 5f 13 [0-20] 61 20 ff 00 00 00 5f 13 [0-20] 58 20 00 01 00 00 5e 13 [0-50] 95 61 28 ?? 00 00 0a 9c 11 ?? 17 58 13 ?? ?? ?? 07 8e 69 3f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_EFAA_2147902854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.EFAA!MTB"
        threat_id = "2147902854"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 07 06 8e 69 5d 91 11 0b 61 13 0c 06 11 09 06 8e 69 5d 91 13 0d 11 0c 11 0d 20 00 01 00 00 58 59 13 0e 06 07 06}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_EHAA_2147902870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.EHAA!MTB"
        threat_id = "2147902870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 07 8e 69 20 00 04 00 00 2e f0 08 15 3e ?? 00 00 00 07 28 ?? 00 00 2b 28 ?? 00 00 2b 0b}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_FEAA_2147903192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.FEAA!MTB"
        threat_id = "2147903192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 14 0d 28 ?? 00 00 0a 2c 0d 08 28 ?? 00 00 0a 08 28 ?? 00 00 0a 0d}  //weight: 4, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_FLAA_2147903199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.FLAA!MTB"
        threat_id = "2147903199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 08 58 0b 08 17 58 0c 08 02 31 f4}  //weight: 4, accuracy: High
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_FQAA_2147903470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.FQAA!MTB"
        threat_id = "2147903470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 11 04 2c eb dd ?? 00 00 00 26 dd 00 00 00 00 11 04 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_FWAA_2147903690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.FWAA!MTB"
        threat_id = "2147903690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {14 0a 38 1c 00 00 00 00 28 ?? 00 00 06 0a 06 16 06 8e 69 28 ?? 00 00 0a dd ?? 00 00 00 26 dd 00 00 00 00 06 2c e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_FZAA_2147903729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.FZAA!MTB"
        threat_id = "2147903729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 0c 17 0d 2b 08 08 09 58 0c 09 17 58 0d 19 2c c9 1c 2c ec 09 02 31 ee}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_KAC_2147903769_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.KAC!MTB"
        threat_id = "2147903769"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "remisat.com.uy" ascii //weight: 2
        $x_2_2 = "DownloadData" ascii //weight: 2
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_GCAA_2147903867_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.GCAA!MTB"
        threat_id = "2147903867"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 16 11 00 8e 69 28 ?? 00 00 0a 20 00 00 00 00 7e ?? 1d 00 04 7b ?? 1d 00 04 3a ?? ff ff ff 26}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_GFAA_2147903917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.GFAA!MTB"
        threat_id = "2147903917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 16 11 05 8e 69 28 ?? 00 00 0a 20 00 00 00 00 7e ?? 1d 00 04 7b ?? 1d 00 04 3a ?? ff ff ff 26}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_GJAA_2147904106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.GJAA!MTB"
        threat_id = "2147904106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0b 06 07 28 ?? 00 00 2b 28 ?? 00 00 2b 16 07 8e 69 6f ?? 00 00 0a dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_GOAA_2147904297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.GOAA!MTB"
        threat_id = "2147904297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 09 07 09 91 18 8d ?? 00 00 01 25 16 20 ?? 00 00 00 9c 25 17 20 ?? 00 00 00 9c 09 18 5d 91 61 d2 9c 00 09 17 58 0d 09 07 8e 69 fe 04 13 04 11 04 2d cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_GTAA_2147904421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.GTAA!MTB"
        threat_id = "2147904421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {38 2b 00 00 00 11 03 16 11 03 8e 69 28 ?? 00 00 0a 20 00 00 00 00 7e}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_HAAA_2147904638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.HAAA!MTB"
        threat_id = "2147904638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 11 06 18 6f ?? 00 00 0a 11 06 11 05 08 6f ?? 00 00 0a 13 07 09 73 ?? 00 00 0a 13 08 11 08 11 07 16 73 ?? 00 00 0a 13 09 11 09 28 ?? 00 00 0a 73 ?? 00 00 0a 13 0a 11 0a 6f ?? 00 00 0a 13 0b dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_HBAA_2147904671_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.HBAA!MTB"
        threat_id = "2147904671"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 05 11 01 28 ?? 00 00 2b 28 ?? 00 00 2b 16 11 01 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_HFAA_2147904836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.HFAA!MTB"
        threat_id = "2147904836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0b 2b 2a 00 02 7b ?? 00 00 04 07 02 7b ?? 00 00 04 07 91 17 8d ?? 00 00 01 25 16 20 ?? 00 00 00 9c 07 17 5d 91 61 d2 9c 00 07 17 58 0b 07 02 7b ?? 00 00 04 8e 69 fe 04 0c 08 2d c7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_HLAA_2147904947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.HLAA!MTB"
        threat_id = "2147904947"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 01 11 03 11 04 11 03 91 11 02 11 03 11 02 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 d2 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_HPAA_2147905052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.HPAA!MTB"
        threat_id = "2147905052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 0a 06 28 ?? 00 00 0a 02 06 28 ?? 00 00 0a 7d ?? 00 00 04 dd ?? 00 00 00 26 dd 00 00 00 00 06 2c d9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_HRAA_2147905086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.HRAA!MTB"
        threat_id = "2147905086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {14 13 04 38 1a 00 00 00 00 28 ?? 00 00 06 13 04 11 04 28 ?? 00 00 0a dd ?? 00 00 00 26 dd 00 00 00 00 11 04 2c e2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_HUAA_2147905153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.HUAA!MTB"
        threat_id = "2147905153"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 15 31 0c 07 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 28 ?? ?? 00 0a 07 6f ?? ?? 00 0a 0d 07 2c 2b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_IDAA_2147905419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.IDAA!MTB"
        threat_id = "2147905419"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 07 11 0d 9c 08 11 13 7b ?? 00 00 04 91 08 07 91 58 20 00 01 00 00 5d 13 0e 05 11 0c 8f ?? 00 00 01 25 71 ?? 00 00 01 08 11 0e 7e ?? 00 00 04 28 ?? 03 00 06 a5 ?? 00 00 01 61 d2 81 ?? 00 00 01 1f 0a 8d ?? 00 00 01 13 0f 16 13 10}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_KAE_2147905519_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.KAE!MTB"
        threat_id = "2147905519"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "//jofilesjo.com" ascii //weight: 2
        $x_2_2 = "DownloadData" ascii //weight: 2
        $x_1_3 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_IGAA_2147905538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.IGAA!MTB"
        threat_id = "2147905538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 28 ?? 00 00 06 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_IPAA_2147905779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.IPAA!MTB"
        threat_id = "2147905779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 00 07 06 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 28 ?? 00 00 06 73 ?? 00 00 0a 13 04 00 11 04 08 16 73 ?? 00 00 0a 13 05 00 11 05 09 6f ?? 00 00 0a 00 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_JOAA_2147906448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.JOAA!MTB"
        threat_id = "2147906448"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 00 11 01 11 00 11 02 94 02 11 02 11 01 28 ?? ?? 00 06 58 9e}  //weight: 2, accuracy: Low
        $x_2_2 = {11 00 11 02 94 02 11 02 11 01 28 ?? ?? 00 06 58 11 00 11 01 94}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_2147906645_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer!MTB"
        threat_id = "2147906645"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "52"
        strings_accuracy = "High"
    strings:
        $x_50_1 = "$61741d91-e58f-4bc5-bf12-83e3ea7b0a53" ascii //weight: 50
        $x_1_2 = "{11111-22222-" ascii //weight: 1
        $x_1_3 = "Base64String" ascii //weight: 1
        $x_1_4 = "DebuggingModes" ascii //weight: 1
        $x_1_5 = "GetBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PureLogStealer_JUAA_2147906677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.JUAA!MTB"
        threat_id = "2147906677"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 00 11 04 28 ?? 00 00 2b 28 ?? 00 00 2b 16 11 04 8e 69 28 ?? 00 00 06 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_KAAA_2147907042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.KAAA!MTB"
        threat_id = "2147907042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {2b 19 2b 1a 2b 1f 2b 20 2b 21 7d ?? 00 00 04 de 24 28 ?? 00 00 06 2b e4 0a 2b e5 06 2b e4 28 ?? 00 00 0a 2b df 02 2b de 06 2b dd 28 ?? 00 00 0a 2b d8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_KDAA_2147907057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.KDAA!MTB"
        threat_id = "2147907057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 08 72 6d 00 00 70 28 ?? 00 00 0a 72 9f 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 09 73 ?? 00 00 0a 13 0a 11 07 73 ?? 00 00 0a 13 0b 11 0b 11 09 16 73 ?? 00 00 0a 13 0c 11 0c 11 0a 6f ?? 00 00 0a 11 0a 6f ?? 00 00 0a 13 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_KEAA_2147907235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.KEAA!MTB"
        threat_id = "2147907235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {14 0a 02 16 3e 19 00 00 00 02 18 5d 3a 11 00 00 00 28 ?? 00 00 06 0a 28 ?? 00 00 0a 06 28 ?? 00 00 0a 28 ?? 00 00 0a 06 6f}  //weight: 5, accuracy: Low
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_KHAA_2147907481_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.KHAA!MTB"
        threat_id = "2147907481"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 07 73 ?? 00 00 0a 13 04 11 04 74 ?? 00 00 01 11 07 75 ?? 00 00 01 17 73 ?? 00 00 0a 13 05 11 05 75 ?? 00 00 01 02 16 02 8e 69 6f ?? 00 00 0a 11 05 75 ?? 00 00 01 6f ?? 00 00 0a 11 04 75 ?? 00 00 01 6f ?? 00 00 0a 0c}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_GMK_2147907807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.GMK!MTB"
        threat_id = "2147907807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 0a 11 0a 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 13 0f 73 ?? ?? ?? ?? 13 0b 11 07 73 ?? ?? ?? ?? 13 0c 11 0c 11 0f 16 73 ?? ?? ?? ?? 13 0d 11 0d 11 0b 6f ?? ?? ?? 0a 11 0b 6f ?? ?? ?? 0a 13 07 de 08 11 0d 6f ?? ?? ?? 0a dc de 08}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_KRAA_2147907818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.KRAA!MTB"
        threat_id = "2147907818"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 07 20 b3 72 2f fe 28 ?? 03 00 06 28 ?? 03 00 06 20 52 72 2f fe 28 ?? 03 00 06 28 ?? 00 00 0a 28 ?? 03 00 06 13 0b}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_KSAA_2147907886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.KSAA!MTB"
        threat_id = "2147907886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 06 11 0a 16 11 0a 8e 69 6f ?? 00 00 0a 13 07 20 00 00 00 00 28}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_LAAA_2147908227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.LAAA!MTB"
        threat_id = "2147908227"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0c 38 24 00 00 00 02 7b ?? 00 00 04 7b ?? 00 00 04 07 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 58 0c 08 07 6f ?? 00 00 0a 32 d3}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_LFAA_2147908410_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.LFAA!MTB"
        threat_id = "2147908410"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {16 0c 2b 24 02 7b ?? 00 00 04 7b ?? 00 00 04 07 08 16 6f ?? 00 00 0a 0d 12 03 28 ?? 00 00 0a 6f ?? 00 00 0a 08 17 58 0c 08 07 6f ?? 00 00 0a 32 d3}  //weight: 4, accuracy: Low
        $x_1_2 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_LRAA_2147909042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.LRAA!MTB"
        threat_id = "2147909042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 72 41 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 9b 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 07 6f ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 06 13 05 11 04 11 05 16 11 05 8e 69 6f ?? 00 00 0a 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_LTAA_2147909156_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.LTAA!MTB"
        threat_id = "2147909156"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 20 b2 b7 b5 c0 28 ?? 00 00 06 28 ?? 00 00 0a 20 91 b7 b5 c0 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 0b 11 04 73 ?? 00 00 0a 0c 08 11 05 16 73 ?? 00 00 0a 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_LUAA_2147909170_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.LUAA!MTB"
        threat_id = "2147909170"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 0e 17 58 11 07 5d 13 11 11 06 11 0e 91 11 10 61 11 06 11 11 91 59 13 12 11 12 20 00 01 00 00 58 13 13 11 06 11 0e 11 13 20 ff 00 00 00 5f d2 9c 00 11 0e 17 58 13 0e}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_LVAA_2147909187_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.LVAA!MTB"
        threat_id = "2147909187"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 11 04 91 11 10 61 11 05 11 11 91 59 13 12 11 12 20 00 01 00 00 58 13 13 11 05 11 04 11 13 d2 9c 11 04 17 58 13 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_LXAA_2147909283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.LXAA!MTB"
        threat_id = "2147909283"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 17 58 08 5d 13 09}  //weight: 2, accuracy: High
        $x_2_2 = {07 11 06 91 11 08 61 07 11 09 91 59 20 00 01 00 00 58 13 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_MEAA_2147909745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.MEAA!MTB"
        threat_id = "2147909745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff ff 00 11 08 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 02}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_MFAA_2147909746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.MFAA!MTB"
        threat_id = "2147909746"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 17 73 ?? 00 00 0a 13 07 11 07 06 16 06 8e 69 6f ?? 00 00 0a 11 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_MGAA_2147909843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.MGAA!MTB"
        threat_id = "2147909843"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff ff 00 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 0f}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ASL_2147910127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ASL!MTB"
        threat_id = "2147910127"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff ff 00 11 01 72 ?? 00 00 70 28 ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 13 02}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_MQAA_2147910174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.MQAA!MTB"
        threat_id = "2147910174"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 05 73 ?? 00 00 0a 0b 11 04 73 ?? 00 00 0a 0c 08 11 05 16 73 ?? 00 00 0a 0d 2b 0a 2b 0b 2b 0c 2b 11 2b 12 de 32 09 2b f3 07 2b f2 6f ?? 00 00 0a 2b ed}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_MRAA_2147910194_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.MRAA!MTB"
        threat_id = "2147910194"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 07 20 ?? ?? 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 20 ?? ?? 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 06 73 ?? 00 00 0a 13 04 11 04 08 16 73 ?? 00 00 0a 13 05 11 05 09 6f ?? 00 00 0a 09}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_MXAA_2147910517_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.MXAA!MTB"
        threat_id = "2147910517"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 09 d4 11 07 09 d4 91 07 07 06 95 07 08 95 58 20 ff 00 00 00 5f 95 61 28 ?? 00 00 0a 9c 09 17 6a 58 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_NAAA_2147910654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.NAAA!MTB"
        threat_id = "2147910654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 13 00 07 09 07 09 91 20 ?? ?? 00 00 59 d2 9c 00 09 17 58 0d 09 07 8e 69 fe 04 13 04 11 04 2d e1}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_NSAA_2147911476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.NSAA!MTB"
        threat_id = "2147911476"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 13 05 11 05 20 00 01 00 00 6f ?? 00 00 0a 11 05 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 05 11 05 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06}  //weight: 2, accuracy: Low
        $x_2_2 = {1a 8d 1d 00 00 01 13 0b 11 0a 11 0b 16 1a 6f ?? 00 00 0a 26 11 0b 16 28 ?? 00 00 0a 26 11 0a 16 73 ?? 00 00 0a 13 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_NYAA_2147911660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.NYAA!MTB"
        threat_id = "2147911660"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 13 04 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05}  //weight: 2, accuracy: Low
        $x_2_2 = {11 07 06 16 06 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 13 08 11 08 6f ?? 00 00 0a 28 ?? 00 00 0a 11 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_OAAA_2147911859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.OAAA!MTB"
        threat_id = "2147911859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 2d 04 2b 04 2b 09 de 0d 28 ?? 00 00 06 2b f5 0a 2b f4 26 de 00}  //weight: 2, accuracy: Low
        $x_2_2 = {16 13 05 11 04 12 05 28 ?? 00 00 0a 08 07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 6f ?? 00 00 0a de 0c 11 05 2c 07 11 04 28 ?? 00 00 0a dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_PCAA_2147912712_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.PCAA!MTB"
        threat_id = "2147912712"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 08 72 01 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 72 5b 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {13 09 11 08 11 09 16 1a 6f ?? 00 00 0a 26 11 09 16 28 ?? 00 00 0a 13 0a 11 08 16 73 ?? 00 00 0a 13 0b 11 0b 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0a}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_PLAA_2147913764_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.PLAA!MTB"
        threat_id = "2147913764"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 04 11 04 16 3f 08 00 00 00 08 11 04 6f ?? 00 00 0a 09 18 58 0d 09 07 6f ?? 00 00 0a 32 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SPGF_2147913856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SPGF!MTB"
        threat_id = "2147913856"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 13 04 11 04 16 32 08 08 11 04 6f ?? 00 00 0a 09 18 58 0d 09 07 6f ?? 00 00 0a 32 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_RDL_2147914224_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.RDL!MTB"
        threat_id = "2147914224"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 08 11 04 6f 1f 00 00 0a 13 07 11 06 11 07 16 73 20 00 00 0a 13 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_RDM_2147914335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.RDM!MTB"
        threat_id = "2147914335"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 11 00 00 0a 6f 12 00 00 0a 0b 73 0e 00 00 0a 0c 08 07 17 73 13 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_RDBA_2147914452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.RDBA!MTB"
        threat_id = "2147914452"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 08 11 04 6f 1c 00 00 0a 13 07 11 06 11 07 16 73 1d 00 00 0a 13 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_QIAA_2147914551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.QIAA!MTB"
        threat_id = "2147914551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0d 00 00 0a 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 ?? 00 00 06 13 04 09 11 04 6f ?? 00 00 0a 16 11 04 6f ?? 00 00 0a 8e 69 6f ?? 00 00 0a 11 04}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SJPL_2147914658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SJPL!MTB"
        threat_id = "2147914658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0b 73 0f 00 00 0a 0c 08 07 17 73 14 00 00 0a 0d 28 ?? 00 00 06 13 04 09 11 04 6f ?? 00 00 0a 16 11 04 6f ?? 00 00 0a 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 08 13 05 dd 1a 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SSGL_2147914670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SSGL!MTB"
        threat_id = "2147914670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 02 04 1f 16 5d 6f ?? ?? ?? 0a 61 28 ?? ?? ?? 06 03 04 17 58 20 ?? ?? ?? 00 5d 91 28 ?? ?? ?? 06 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? ?? ?? 06 9c 03 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_QNAA_2147914749_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.QNAA!MTB"
        threat_id = "2147914749"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 ?? 00 00 06 13 04 09 11 04 6f ?? 00 00 0a 16 11 04}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_RDF_2147914891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.RDF!MTB"
        threat_id = "2147914891"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 06 09 08 11 04 6f ?? ?? ?? ?? 13 07 11 06 11 07 16}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_QRAA_2147915057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.QRAA!MTB"
        threat_id = "2147915057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 01 20 9f ab a6 d6 28 ?? 05 00 06 28 ?? 04 00 0a 20 bc ab a6 d6 28 ?? 06 00 06 28 ?? 06 00 06 6f ?? 05 00 0a 13 06}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_QSAA_2147915066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.QSAA!MTB"
        threat_id = "2147915066"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 39 9e 00 00 00 26 06 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SPZF_2147915073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SPZF!MTB"
        threat_id = "2147915073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 16 11 19 11 09 91 13 28 11 19 11 09 11 20 11 28 61 11 18 19 58 61 11 32 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_RDN_2147915831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.RDN!MTB"
        threat_id = "2147915831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "e1f2a3b4-c5d6-7890-abcd-12345ef67890" ascii //weight: 2
        $x_1_2 = "VertexDynamics" ascii //weight: 1
        $x_1_3 = "Engineering next-gen solutions for today's challenges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_RNAA_2147916097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.RNAA!MTB"
        threat_id = "2147916097"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 08 6f ?? 00 00 0a 73 ?? 00 00 0a 13 06 1a 8d ?? 00 00 01 13 07 11 06 11 07 16 1a 6f ?? 00 00 0a 26 11 07 16 28 ?? 00 00 0a 13 08 11 06 16 73 ?? 00 00 0a 13 09 11 09 11 05 6f ?? 00 00 0a 73 ?? 00 00 0a 13 0a 11 0a 11 05 6f ?? 00 00 0a 6f ?? 00 00 0a 11 0a 13 0a de 4e}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SKAA_2147916820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SKAA!MTB"
        threat_id = "2147916820"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 0c 2a 00 11 0b 72 ?? 00 00 70 28 ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 06 13 01 20 00 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 ?? 00 00 00 26}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SOAA_2147916924_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SOAA!MTB"
        threat_id = "2147916924"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 08 72 9f 00 00 70 28 ?? 00 00 06 72 d1 00 00 70 28 ?? 00 00 06 28 ?? 00 00 06 13 06 20 01 00 00 00 7e ?? 00 00 04 7b ?? 00 00 04 39 0f 00 00 00 26}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SVAA_2147917275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SVAA!MTB"
        threat_id = "2147917275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 04 73 ?? 01 00 0a 0b 07 11 04 17 73 ?? 01 00 0a 0c 02 28 ?? ?? 00 06 0d 08 09 16 09 8e 69 6f ?? 01 00 0a 07 13 05 de 0e}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_RDO_2147917891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.RDO!MTB"
        threat_id = "2147917891"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "[System.BitConverter]::GetBytes($L[$i] - 1100)" wide //weight: 2
        $x_1_2 = "$A = [System.Reflection.Assembly]::Load($L)" wide //weight: 1
        $x_1_3 = "$A.CreateInstance('B')" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_RDP_2147917892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.RDP!MTB"
        threat_id = "2147917892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 03 04 6f 29 00 00 0a 0b 02 07 28 39 00 00 06 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_TLAA_2147917952_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.TLAA!MTB"
        threat_id = "2147917952"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {73 13 00 00 0a 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 02 28 ?? 00 00 06 13 04 09 11 04 28 ?? 00 00 2b 16 11 04 28 ?? 00 00 2b 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 05}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_TSAA_2147918307_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.TSAA!MTB"
        threat_id = "2147918307"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 13 0d 2b 17 00 02 11 0d 02 11 0d 91 20 ?? ?? 00 00 59 d2 9c 00 11 0d 17 58 13 0d 11 0d 02 8e 69 fe 04 13 0e 11 0e 2d dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_UAAA_2147918836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.UAAA!MTB"
        threat_id = "2147918836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {07 11 0b 91 11 08 61 11 0a 59 20 00 02 00 00 58 13 0c 11 0c 20 00 01 00 00 5d 20 00 04 00 00 58 20 00 02 00 00 5d 13 0d 11 0d 20 00 01 00 00 59 20 00 04 00 00 58 20 ff 00 00 00 5f 13 0e 07 11 07 11 0e d2 9c 11 07 17 58 13 07}  //weight: 4, accuracy: High
        $x_1_2 = "J7CV4D7U54B5F2ZH845F7Z" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_UCAA_2147919100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.UCAA!MTB"
        threat_id = "2147919100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 07 72 61 00 00 70 28 ?? 00 00 0a 72 93 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? 00 00 0a 09 6f ?? 00 00 0a 0a dd}  //weight: 4, accuracy: Low
        $x_1_2 = "ReadAsByteArrayAsync" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_UDAA_2147919140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.UDAA!MTB"
        threat_id = "2147919140"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 0e 11 10 61 13 11 38}  //weight: 2, accuracy: High
        $x_2_2 = {11 13 11 08 d4 11 11 20 ff 00 00 00 5f 28 ?? 00 00 0a 9c 38}  //weight: 2, accuracy: Low
        $x_1_3 = "80HDF88K4ED0U55PHHG8N4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_UGAA_2147919282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.UGAA!MTB"
        threat_id = "2147919282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0d 09 08 17 73 ?? 00 00 0a 13 04 28 ?? 00 00 06 16 2c 2d 26 11 04 11 05 28 ?? 00 00 2b 16 11 05 28 ?? 00 00 2b 8e 69 16 2c 1a 26 26 26 26 16 2d da 09 6f ?? 00 00 0a 17 2d 11 26 16 2d f0 de 34 13 05 2b d0 6f ?? 00 00 0a 2b e3 0a 2b ed}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_UHAA_2147919298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.UHAA!MTB"
        threat_id = "2147919298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 03 95 11 06 11 04 95 58 d2 13 0f 38}  //weight: 2, accuracy: High
        $x_2_2 = {11 0e 11 10 61 13 13 38}  //weight: 2, accuracy: High
        $x_1_3 = "80HDF88K4ED0U55PHHG8N4" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_VFAA_2147920100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.VFAA!MTB"
        threat_id = "2147920100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 03 11 02 02 11 02 91 11 01 11 02 11 01 28 ?? 00 00 06 5d 28 ?? 00 00 06 61 d2 9c 20}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_VKAA_2147920230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.VKAA!MTB"
        threat_id = "2147920230"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "GyMAbmOFFujFiehEPZOsbV.dll" ascii //weight: 2
        $x_1_2 = "DXBQvWZPsoitAglyAqvF" ascii //weight: 1
        $x_1_3 = "DkXBPNkrUIvokvAKWOOcKL.dll" ascii //weight: 1
        $x_1_4 = "ujefeQtTSqQEitmguxXZXgF" ascii //weight: 1
        $x_1_5 = "vysLTwxigwwMGJpcQbTPB.dll" ascii //weight: 1
        $x_1_6 = "oVQNoeTvJrddFnuCjqBvwbCc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AMAK_2147920527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AMAK!MTB"
        threat_id = "2147920527"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 25 17 6f ?? 00 00 0a 25 18 6f ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 2b 28 ?? 00 00 06 28 ?? 00 00 2b 6f ?? 00 00 0a 0a 06 02 16 02 8e 69 6f ?? 00 00 0a 0b de 0a}  //weight: 3, accuracy: Low
        $x_1_2 = {0a 14 1a 8d ?? 00 00 01 25 16 02 a2 25 17 03 a2 25 18 06 8c ?? 00 00 01 a2 25 19 04 a2}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_MBXT_2147920544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.MBXT!MTB"
        threat_id = "2147920544"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {71 52 44 77 41 4d 4f 39 00 64 51 45 76 61 6e 42 54 34 36 71 6a 66 55 48}  //weight: 3, accuracy: High
        $x_2_2 = "MeshEkran.DataSetler.FirmaDBListD" ascii //weight: 2
        $x_1_3 = "df5a2458cb35" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_KAF_2147920798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.KAF!MTB"
        threat_id = "2147920798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 3a 08 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ACBA_2147924100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ACBA!MTB"
        threat_id = "2147924100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {16 39 9e 00 00 00 26 06 72 ?? 02 00 70 28 ?? 00 00 0a 72 ?? 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 08 07 17 73 ?? 00 00 0a 0d 2b 29 2b 2e 2b 30 2b 31 2b 33 16 2b 37 2b 39 8e 69 6f ?? 00 00 0a 11 04}  //weight: 3, accuracy: Low
        $x_2_2 = {16 2d f6 08 13 05 1e 2c f0 19 2c f4 de 3b 28 ?? 00 00 06 2b d0 13 04 2b ce 09 2b cd 11 04 2b cb 6f ?? 00 00 0a 2b c6 11 04 2b c5 6f ?? 00 00 0a 2b c0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SZZB_2147924276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SZZB!MTB"
        threat_id = "2147924276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 1f 10 8d 1a 00 00 01 25 d0 50 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 57 00 00 0a 25 02 16 02 8e 69 6f ?? 00 00 0a 6f}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AGBA_2147924285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AGBA!MTB"
        threat_id = "2147924285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 73 0b 00 00 0a 0c 08 06 07 6f ?? 00 00 0a 0d 73 0d 00 00 0a 13 04 11 04 09 17 73 0e 00 00 0a 13 05 11 05 7e 02 00 00 04 16 7e 02 00 00 04 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 80 02 00 00 04 de 18}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ABDA_2147926036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ABDA!MTB"
        threat_id = "2147926036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {29 00 00 0a 0a 02 28 ?? 00 00 2b 6f ?? 00 00 0a 0b 38 0e 00 00 00 07 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 2d ea dd 0d 00 00 00 07 39 06 00 00 00 07 6f ?? 00 00 0a dc 06 6f ?? 00 00 0a 2a}  //weight: 3, accuracy: Low
        $x_2_2 = "GetExp ortedT ypes" wide //weight: 2
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AGEA_2147926859_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AGEA!MTB"
        threat_id = "2147926859"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {95 58 20 ff 00 00 00 5f 13 0b 11 0b 1f 7b 61 20 ff 00 00 00 5f 13 0c 11 0c 20 c8 01 00 00 58 20 00 01 00 00 5e 13 0c 11 0c 2c 04 11 0c 2b 01 17 13 0c 09 11 0a 07 11 0a 91 11 04 11 0b 95 61 28 ?? 00 00 0a 9c 00 11 0a 17 58 13 0a 11 0a 07 8e 69 fe 04 13 0d 11 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AKEA_2147927033_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AKEA!MTB"
        threat_id = "2147927033"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 19 8d d9 00 00 01 25 16 12 00 28 ?? 00 00 0a 9c 25 17 12 00 28 ?? 00 00 0a 9c 25 18 12 00 28 ?? 00 00 0a 9c 07 28 ?? 00 00 2b 6f ?? 00 00 0a 11 05}  //weight: 3, accuracy: Low
        $x_2_2 = {03 09 1f 10 63 20 ff 00 00 00 5f d2 6f 8f 00 00 0a}  //weight: 2, accuracy: High
        $x_1_3 = "GetPixel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AOEA_2147927113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AOEA!MTB"
        threat_id = "2147927113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {06 0a 06 02 7d 38 00 00 04 00 16 06 7b 38 00 00 04 6f ?? 00 00 0a 18 5b 28 ?? 00 00 0a 06 fe ?? ?? 00 00 06 73 7e 00 00 0a 28 ?? 00 00 2b 28 ?? 00 00 2b 0b 2b 00 07 2a}  //weight: 4, accuracy: Low
        $x_2_2 = "Proyecto.NET" wide //weight: 2
        $x_2_3 = "4D5A9__3___04___FFFF__B8_______4___________________________________08" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AMCO_2147927216_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AMCO!MTB"
        threat_id = "2147927216"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 9c 25 17 12 00 28 ?? 00 00 0a 9c 25 18 12 00 28 ?? 00 00 0a 9c 07 28 06 00 00 2b}  //weight: 4, accuracy: Low
        $x_1_2 = {1f 10 62 12 00 28 ?? 00 00 0a 1e 62 60 12 00 28 ?? 00 00 0a 60 0c 03 08 1f 10 63 20 ff 00 00 00 5f d2 6f ?? 00 00 0a 03 08 1e 63 20 ff 00 00 00 5f d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ASFA_2147928017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ASFA!MTB"
        threat_id = "2147928017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 11 08 28 ?? 02 00 06 17 73 ?? 01 00 0a 13 0c 20 00 00 00 00 7e ?? 02 00 04 39 ?? ff ff ff 26}  //weight: 3, accuracy: Low
        $x_3_2 = {11 0c 02 16 02 8e 69 28 ?? 02 00 06 20 00 00 00 00 7e ?? 02 00 04 3a ?? 00 00 00 26}  //weight: 3, accuracy: Low
        $x_2_3 = "F4A685CA111882879036.g.resources" ascii //weight: 2
        $x_2_4 = "rKWJTiBuK1FSkuZvDy.XM7D23CHuvbooqaBrU" ascii //weight: 2
        $x_2_5 = "YHg8aAJxoeft8ja7nM.yJ3itPKfvVOmJkkoc8" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_PKLH_2147928108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.PKLH!MTB"
        threat_id = "2147928108"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_8_1 = {0b 14 0c 2b [0-20] 08 16 08 8e 69 6f ?? 00 00 0a 0d de 0a 06 2c 06 06 6f ?? 00 00 0a dc}  //weight: 8, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_APU_2147928882_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.APU!MTB"
        threat_id = "2147928882"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 00 02 06 16 06 8e 69 6f ?? 00 00 0a 0b 07 16 31 12 28 ?? 00 00 0a 06 16 07 6f ?? 00 00 0a 28}  //weight: 2, accuracy: Low
        $x_3_2 = "193.58.121.250" wide //weight: 3
        $x_1_3 = "Connected to server" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AHIA_2147930032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AHIA!MTB"
        threat_id = "2147930032"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0a 2b 1b 00 7e ?? 00 00 04 06 7e ?? 00 00 04 06 91 20 ?? 03 00 00 59 d2 9c 00 06 17 58 0a 06 7e ?? 00 00 04 8e 69 fe 04 0b 07 2d d7}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AUIA_2147930815_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AUIA!MTB"
        threat_id = "2147930815"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 20 00 01 00 00 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 06 6f ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c}  //weight: 4, accuracy: Low
        $x_2_2 = {0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 08 6f}  //weight: 2, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AEJA_2147931183_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AEJA!MTB"
        threat_id = "2147931183"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 17 58 72 f8 00 00 70 28 ?? 00 00 0a 5d 0c 09 06 08 91 58 20 00 01 00 00 5d 0d 06 09 91 13 08 06 09 06 08 91 9c 06 08 11 08 9c dd}  //weight: 3, accuracy: Low
        $x_2_2 = {06 08 91 06 09 91 58 72 f8 00 00 70 28 ?? 00 00 0a 5d 13 06 73 ?? 00 00 0a 13 07 11 07 06 11 06 91 6f ?? 00 00 0a 02 11 05 8f ?? 00 00 01 25 47 11 07 16 6f ?? 00 00 0a 61 d2 52 11 05 17 58 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_MBWQ_2147931371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.MBWQ!MTB"
        threat_id = "2147931371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {07 11 08 1f 14 58 28 ?? 00 00 0a 13 09 07 11 08 1f 10}  //weight: 3, accuracy: Low
        $x_1_2 = "DhxlvGNVKJNI41jioT" ascii //weight: 1
        $x_1_3 = "ebaFt4YcOfYaVEJN3P" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_PureLogStealer_ADCA_2147932392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ADCA!MTB"
        threat_id = "2147932392"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 72 43 00 00 70 28 ?? 00 00 0a 72 75 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00 0a 0c 02 7b ?? 00 00 04 75 ?? 00 00 1b 73 ?? 00 00 0a 0d 09 07 16 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 02 08 6f ?? 00 00 0a 7d ?? 00 00 04 dd ?? 00 00 00 11 04 39 ?? 00 00 00 11 04 6f ?? 00 00 0a dc}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AVMA_2147935006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AVMA!MTB"
        threat_id = "2147935006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0c dd}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AJNA_2147935398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AJNA!MTB"
        threat_id = "2147935398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 03 6f ?? 00 00 0a 06 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 07 20 ?? ?? 00 00 28 ?? ?? 00 06 28 ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0c de 1b}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ANNA_2147935549_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ANNA!MTB"
        threat_id = "2147935549"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 03 6f ?? 00 00 0a 06 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d de 1f}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_APNA_2147935714_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.APNA!MTB"
        threat_id = "2147935714"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 03 6f ?? 00 00 0a 06 04 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 0d dd 2e}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_HHX_2147935935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.HHX!MTB"
        threat_id = "2147935935"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 06 28 ?? 24 00 06 28 ?? 25 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ABOA_2147936057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ABOA!MTB"
        threat_id = "2147936057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 de 40}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ACOA_2147936086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ACOA!MTB"
        threat_id = "2147936086"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0a 06 11 04 6f ?? 00 00 0a 06 11 05 6f ?? 00 00 0a 73 ?? 00 00 0a 0b 07 06 6f ?? 00 00 0a 17 73 ?? 00 00 0a 0c 08 02 16 02 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 07 6f ?? 00 00 0a 13 06 de 35}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AOOA_2147936452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AOOA!MTB"
        threat_id = "2147936452"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 04 11 04 17 6f ?? 00 00 0a 11 04 18 6f ?? 00 00 0a 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 02 16 02 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a dd 0f}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SHPA_2147936563_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SHPA!MTB"
        threat_id = "2147936563"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 d1 13 12 11 1c 11 09 91 13 22 11 1c 11 09 11 26 11 22 61 11 1b 19 58 61 11 32 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SXDA_2147936678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SXDA!MTB"
        threat_id = "2147936678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 d1 13 12 11 1c 11 09 91 13 22 11 1c 11 09 11 26 11 22 61 19 11 1b 58 61 11 32 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AGPA_2147937028_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AGPA!MTB"
        threat_id = "2147937028"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 2b 28 72 ?? ?? 00 70 2b 24 2b 29 16 2d f2 2b 2b 72 ?? ?? 00 70 2b 27 2b 2c 2b 31 2b 32 06 16 06 8e 69 6f ?? 00 00 0a 0c de 41 07 2b d5 28 ?? ?? 00 0a 2b d5 6f ?? ?? 00 0a 2b d0 07 2b d2 28 ?? ?? 00 0a 2b d2 6f ?? ?? 00 0a 2b cd 07 2b cc 6f ?? ?? 00 0a 2b c7}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SDFO_2147937031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SDFO!MTB"
        threat_id = "2147937031"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 d1 13 12 11 1c 11 09 91 13 22 11 1c 11 09 11 22 11 26 61 19 11 1b 58 61 11 32 61 d2 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AQPA_2147937367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AQPA!MTB"
        threat_id = "2147937367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {2b 1b 2b 1c 2b 21 73 ?? 00 00 0a 25 72 ?? ?? 00 70 2b 17 2b 1c 2b 1d 2b 22 2b 27 de 2d 02 2b e2 28 ?? 00 00 06 2b dd 0a 2b dc 28 ?? 00 00 0a 2b e2 06 2b e1 28 ?? 00 00 06 2b dc 6f ?? 00 00 0a 2b d7 0b 2b d6}  //weight: 3, accuracy: Low
        $x_2_2 = {08 02 59 07 59 20 ff 00 00 00 25 2c f7 5f 16 2d 15 d2 0c 08 66 16 2d ed d2 0c 06 07 08 9c 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AZPA_2147937823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AZPA!MTB"
        threat_id = "2147937823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ACQA_2147937962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ACQA!MTB"
        threat_id = "2147937962"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 73 ?? 00 00 0a 0d 09 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 09 6f ?? 00 00 0a 13 05 de 20}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ZZK_2147938143_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ZZK!MTB"
        threat_id = "2147938143"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 13 0e 16 13 0f 2b 14}  //weight: 6, accuracy: Low
        $x_5_2 = {03 07 11 04 6f ?? 00 00 0a 13 05 0e 04 0e 04 4a 17 58 54 23 00 00 00 00 00 00 00 00 13 06 11 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_RPA_2147938161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.RPA!MTB"
        threat_id = "2147938161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Failed to decrypt payload: " wide //weight: 10
        $x_1_2 = "Fetching payload from {0}" wide //weight: 1
        $x_1_3 = "https://example.com/dynamic_code.bin" wide //weight: 1
        $x_10_4 = "Invalid payload source." wide //weight: 10
        $x_1_5 = "DynamicCodeExecutor.dynamic_code.bin" wide //weight: 1
        $x_1_6 = "Loading and executing dynamic code" wide //weight: 1
        $x_1_7 = "Failed to execute dynamic code: " wide //weight: 1
        $x_1_8 = "Entry type not found in dynamic code." wide //weight: 1
        $x_1_9 = "Entry method not found in dynamic code." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AMQA_2147938381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AMQA!MTB"
        threat_id = "2147938381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 2c 07 1a 8d ?? 00 00 01 0b 06 07 16 1a 6f ?? 00 00 0a 26 16 2d 0b 07 16 28 ?? 00 00 0a 19 2c f2 0c 06 16 73 ?? 00 00 0a 0d 2b 1d 1d 2c 10 8d ?? 00 00 01 2b 16 2b 18 2b 19 16 2b 1a 2b 1b 26 11 04 13 05 1e 2c f9 de 2c 08 2b e0 13 04 2b e6 09 2b e5 11 04 2b e3 08 2b e3 6f ?? 00 00 0a 2b de}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ANQA_2147938409_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ANQA!MTB"
        threat_id = "2147938409"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0a 06 72 61 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 72 93 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 06 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 0b dd 0d}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AFRA_2147939279_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AFRA!MTB"
        threat_id = "2147939279"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 06 8e 69 40 02 00 00 00 16 0d 08 11 04 07 11 04 91 06 09 93 7e ?? ?? 00 04 28 ?? ?? 00 06 61 d2 9c 09 17 58 0d 11 04 17 58 13 04 11 04 07 8e 69 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ANRA_2147939569_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ANRA!MTB"
        threat_id = "2147939569"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {03 08 91 0d 09 18 28 ?? 00 00 06 0d 09 06 59 08 59 20 ff 00 00 00 5f d2 0d 09 66 d2 0d 07 08 09 9c 08 17 58 0c 08 03 8e 69 32 d5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AYRA_2147939925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AYRA!MTB"
        threat_id = "2147939925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0a 03 8e 69 1a 59 8d ?? 00 00 01 0b 03 1a 07 16 07 8e 69 28 ?? 00 00 0a 06 28 ?? 00 00 06 0c 07 73 ?? 00 00 0a 0d 09 16 73 ?? 00 00 0a 13 04 16 13 05 38 ?? 00 00 00 11 04 08 11 05 06 11 05 59 6f ?? 00 00 0a 13 06 11 06 39 ?? 00 00 00 11 05 11 06 58 13 05 11 05 06 32 dd 11 05 06 3b ?? 00 00 00 73 ?? 00 00 0a 7a 06 8d ?? 00 00 01 13 07 08 16 11 07 16 06 28 ?? 00 00 0a 11 07 13 08 dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_NP_2147940070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.NP!MTB"
        threat_id = "2147940070"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {7e 2f 00 00 04 07 9a 06 28 79 00 00 0a 39 0b 00 00 00 7e 30 00 00 04 74 1d 00 00 01 2a 07 17 58 0b 07 7e 2f 00 00 04 8e 69 3f d2 ff ff ff}  //weight: 3, accuracy: High
        $x_1_2 = "$95d5eed8-3808-421e-9b11-62d54f0de265" ascii //weight: 1
        $x_1_3 = "JavaScript-plugin.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AFSA_2147940203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AFSA!MTB"
        threat_id = "2147940203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 14 0c 73 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 06 07 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 11 05 03 16 03 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 06 11 06 8e 69 28 ?? 00 00 06 0c 11 06 16 08 16 11 06 8e 69 28 ?? 00 00 0a 08 13 07 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_PNED_2147940440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.PNED!MTB"
        threat_id = "2147940440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 04 11 04 17 6f ?? 00 00 0a 11 04 18 6f ?? 00 00 0a 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 73 0c 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 0e 00 00 0a 13 06 11 06 02 16 02 8e 69 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a de 0c}  //weight: 4, accuracy: Low
        $x_2_2 = {28 13 00 00 0a 7e 17 00 00 04 6f 72 00 00 0a 74 29 00 00 01 fe 09 00 00 8c 41 00 00 01 6f 4d 00 00 0a 74 18 00 00 01 2a}  //weight: 2, accuracy: High
        $x_1_3 = {06 28 05 00 00 0a 0c 07 28 05 00 00 0a 0d de 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AWSA_2147940658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AWSA!MTB"
        threat_id = "2147940658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 1a 8d ?? 00 00 01 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 11 04 8d ?? 00 00 01 13 06 16 13 07 2b 15 11 07 11 05 11 06 11 07 11 04 11 07 59 6f ?? 00 00 0a 58 13 07 11 07 11 04 32 e5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SWA_2147940761_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SWA!MTB"
        threat_id = "2147940761"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 04 00 00 06 25 73 0a 00 00 06 6f ?? 00 00 06 25 73 0c 00 00 06 6f ?? 00 00 06 25 73 0e 00 00 06 6f ?? 00 00 06 25 73 10 00 00 06 6f ?? 00 00 06 6f ?? 00 00 06 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AOTA_2147941155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AOTA!MTB"
        threat_id = "2147941155"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 72 ?? ?? 00 70 13 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 13 07 11 07 11 06 03 28 ?? 00 00 06 de 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AIUA_2147941623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AIUA!MTB"
        threat_id = "2147941623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 09 11 04 6f ?? 00 00 0a 13 05 07 08 16 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 07 08 17 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 07 08 18 12 05 28 ?? 00 00 0a 28 ?? 00 00 0a 08 17 58 0c 11 04 17 58 13 04 11 04 02 6f ?? 00 00 0a 2f 09 03 6f ?? 00 00 0a 04 32 ab}  //weight: 5, accuracy: Low
        $x_2_2 = {03 07 11 06 16 28 ?? 00 00 0a 6f ?? 00 00 0a 03 07 11 06 17 28 ?? 00 00 0a 6f ?? 00 00 0a 03 07 11 06 18 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_MKV_2147941741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.MKV!MTB"
        threat_id = "2147941741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 0a 6f ?? 00 00 0a 20 00 00 00 00 7e 85 00 00 04 7b b5 00 00 04 3a 0f 00 00 00 26 20 01 00 00 00 38 04 00 00 00 fe 0c 03 00 45 04 00 00 00 2d 00 00 00 05 00 00 00 40 00 00 00 63 00 00 00 38 28 00 00 00 11 04 11 07 6f ?? 00 00 0a 20 00 00 00 00 7e 85 00 00 04 7b a5 00 00 04 39 c9 ff ff ff 26 20 00 00 00 00 38 be ff ff ff 11 04 6f ?? 00 00 0a 13 05 20 02 00 00 00 38 ab ff ff ff 03 72 c7 00 00 70 11 05 11 09 16 11 09 8e 69 6f ?? 00 00 0a 6f ?? 00 00 06 20 03 00 00 00 38 88 ff ff ff}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AUUA_2147941995_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AUUA!MTB"
        threat_id = "2147941995"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 12 02 28 ?? 00 00 0a 12 02 28 ?? 00 00 0a 28 ?? 00 00 06 13 08 04 03 6f ?? 00 00 0a 59 13 09 11 09 19 32 29 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 03 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 2b 47 11 09 16 31 42}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 12 08 28 ?? 00 00 0a 9c 25 17 12 08 28 ?? 00 00 0a 9c 25 18 12 08 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ENSY_2147942199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ENSY!MTB"
        threat_id = "2147942199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 11 0b 11 07 91 ?? ?? ?? ?? ?? 11 07 17 58 13 07 11 07 11 09 32 e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_EASS_2147942203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.EASS!MTB"
        threat_id = "2147942203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8f 0c 00 00 01 25 71 0c 00 00 01 11 07 11 08 11 07 8e 69 5d 91 61 d2 81 0c 00 00 01 11 08 17 58 13 08 11 08 11 06 8e}  //weight: 1, accuracy: High
        $x_1_2 = {11 09 11 0a 16 20 00 10 00 00 ?? ?? ?? ?? ?? 13 0c 11 0c 16 31 0c 11 0b 11 0a 16 11 0c ?? ?? ?? ?? ?? 11 0c 16 30 d9}  //weight: 1, accuracy: Low
        $x_1_3 = "hkguTzSCb75g7sJ9ChMcmAOPpeBL9ZJy/tejnoCjT+E=" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AHVA_2147942267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AHVA!MTB"
        threat_id = "2147942267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 06 16 06 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 06 03 72 ?? ?? 00 70 11 06 6f ?? 00 00 06 05 72 ?? ?? 00 70 6f ?? 00 00 0a 17 0b dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AJVA_2147942282_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AJVA!MTB"
        threat_id = "2147942282"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 09 06 07 6f ?? ?? 00 0a 17 73 ?? ?? 00 0a 13 05 16 2d 14 2b 38 2b 3a 16 02 8e 69 6f ?? 00 00 0a 11 05 6f ?? ?? 00 0a 11 04 6f ?? ?? 00 0a 13 06 11 06 8e 69 28 ?? ?? 00 06 0c 11 06 16 08 16 11 06 8e 69 28 ?? ?? 00 0a 08 13 07 de 2c 11 05 2b c4 02 2b c3}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AMVA_2147942368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AMVA!MTB"
        threat_id = "2147942368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 32 2b 34 16 2b 34 8e 69 2b 33 2b 38 2b 3a 2b 3f 2b 41 2b 46 72 ?? ?? 00 70 11 06 03 28 ?? 00 00 06 05 72 ?? ?? 00 70 6f ?? 00 00 0a 17 0b dd ?? 00 00 00 11 05 2b ca 06 2b c9 06 2b c9 6f ?? 00 00 0a 2b c6 11 05 2b c4 6f ?? 00 00 0a 2b bf 11 04 2b bd 6f ?? 00 00 0a 2b b8 13 06 2b b6}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AWVA_2147942872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AWVA!MTB"
        threat_id = "2147942872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 0a 2b 38 04 28 ?? 03 00 06 0b 2b 37 28 ?? 03 00 06 25 06 28 ?? 03 00 06 25 07 28 ?? 03 00 06 25 1f 0f 28 ?? 01 00 06 28 ?? 03 00 06 25 1c 28 ?? 01 00 06 28 ?? 03 00 06 0c 2b 0e 1f c1 1f cb 32 c2 2b 06 1f 85 1f 2c 32 c3 08 28 ?? 03 00 06 0d 09 02 16 28 ?? 01 00 06 02 8e 69 28 ?? 03 00 06 13 04 de 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ADWA_2147943054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ADWA!MTB"
        threat_id = "2147943054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 72 ?? ?? 00 70 13 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 13 07 11 07 03 11 06 28 ?? 00 00 06 de 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AEWA_2147943191_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AEWA!MTB"
        threat_id = "2147943191"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 72 ?? ?? 00 70 13 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 13 07 11 06 11 07 03 28 ?? 00 00 06 de 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ZKT_2147943381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ZKT!MTB"
        threat_id = "2147943381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {08 11 04 07 11 04 91 06 09 93 28 ?? 00 00 0a 61 d2 9c 09 17 58 0d 11 04 17 58 13 04 20 2e 5b 50 7c 00 fe 0e 06 00 00 fe 0d 06 00 48 68 20 2e 5b 6f 15 00 fe 0e 06 00 fe 0d 06 00 48 68 fe 01}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ZQT_2147943584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ZQT!MTB"
        threat_id = "2147943584"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {02 12 07 28 ?? 00 00 0a 12 07 28 ?? 00 00 0a 6f ?? 00 00 0a 13 17 73 ?? 00 00 0a 13 18 11 18 72 8f 02 00 70 09 6f ?? 00 00 0a 23 00 00 00 00 00 80 76 40 5a}  //weight: 6, accuracy: Low
        $x_5_2 = {08 11 18 6f ?? 00 00 0a 00 11 05 72 db 02 00 70 12 17 28 ?? 00 00 0a 12 17 28 ?? 00 00 0a 58 12 17 28 ?? 00 00 0a 58 6b 22 00 00 40 40 5b 22 00 00 7f 43 5b}  //weight: 5, accuracy: Low
        $x_4_3 = {59 13 19 12 07 28 ?? 00 00 0a 1f 14 5d 2d 0c 11 04 6f ?? 00 00 0a 16 fe 02 2b 01 16}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ALXA_2147944423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ALXA!MTB"
        threat_id = "2147944423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 28 ?? 00 00 0a 13 01 38 ?? ?? 00 00 11 07 2a 00 11 02 20 00 01 00 00 6f ?? 00 00 0a 38 00 00 00 00 11 02 11 00 6f ?? 00 00 0a 38 00 00 00 00 11 02 11 01 6f ?? 00 00 0a 38 00 00 00 00 11 02 6f ?? 00 00 0a 13 03 38 00 00 00 00 00 02 73 ?? 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 ?? 00 00 0a 13 05 38 00 00 00 00 00 73 ?? 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 6f ?? 00 00 0a 38 00 00 00 00 11 06 6f ?? 00 00 0a 13 07 38 00 00 00 00 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AMXA_2147944465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AMXA!MTB"
        threat_id = "2147944465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 01 00 00 70 28 ?? 00 00 0a 13 01 38 ?? 00 00 00 11 07 2a 28 ?? 00 00 0a 13 02 38 00 00 00 00 00 11 02 20 00 01 00 00 6f ?? 00 00 0a 38 00 00 00 00 11 02 11 00 6f ?? 00 00 0a 38 ?? 00 00 00 11 02 6f ?? 00 00 0a 13 03 38 ?? 00 00 00 11 02 11 01 6f ?? 00 00 0a 38 ?? ff ff ff 00 02 73 ?? 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 ?? 00 00 0a 13 05 38 00 00 00 00 00 73 ?? 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 6f ?? 00 00 0a 38 00 00 00 00 11 06 6f ?? 00 00 0a 13 07 38 00 00 00 00 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AOYA_2147945472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AOYA!MTB"
        threat_id = "2147945472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1e 2d 4d 26 2b 4d 8e 69 8d ?? 00 00 01 2b 47 72 ?? ?? 00 70 1a 2d 42 26 16 2b 41 2b 1b 2b 40 09 06 09 91 08 09 08 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 df 07 0a de 23 73 ?? 00 00 0a 2b b0 28 ?? 00 00 0a 2b b0 0a 2b b1 06 2b b0 0b 2b b6 0c 2b bc 0d 2b bc 07 2b bd 26 de 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AETA_2147946009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AETA!MTB"
        threat_id = "2147946009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 02 08 28 ?? 00 00 06 0d 09 8d ?? 00 00 01 13 04 08 16 73 ?? 00 00 0a 13 05 02 11 05 11 04 16 09 28 ?? 00 00 06 dd 0f 00 00 00 11 05 39 07 00 00 00 11 05 6f ?? 00 00 0a dc 03 72 c7 00 00 70 11 04 6f ?? 00 00 06 17 0b dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ANZA_2147946284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ANZA!MTB"
        threat_id = "2147946284"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 01 38 00 00 00 00 28 ?? 00 00 0a 13 02 38 ?? 00 00 00 11 07 2a 72 ?? 00 00 70 28 ?? 00 00 0a 13 00 38 ?? ff ff ff 00 11 02 20 00 01 00 00 6f ?? 00 00 0a 38 00 00 00 00 11 02 11 00 6f ?? 00 00 0a 38 00 00 00 00 11 02 11 01 6f ?? 00 00 0a 38 00 00 00 00 11 02 6f ?? 00 00 0a 13 03 38 00 00 00 00 00 02 73 ?? 00 00 0a 13 04 38 00 00 00 00 00 11 04 11 03 16 73 ?? 00 00 0a 13 05 38 00 00 00 00 00 73 ?? 00 00 0a 13 06 38 00 00 00 00 00 11 05 11 06 6f ?? 00 00 0a 38 00 00 00 00 11 06 6f ?? 00 00 0a 13 07 38 00 00 00 00 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AYAB_2147947623_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AYAB!MTB"
        threat_id = "2147947623"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 06 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 14 13 04 38 be 00 00 00 00 20 00 0c 00 00 28 ?? 00 00 0a dd ?? 00 00 00 26 dd 00 00 00 00 73 ?? 00 00 0a 13 05 11 05 72 ?? 00 00 70 73 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 13 06 73 ?? 00 00 0a 13 07 11 06 11 07 6f ?? 00 00 0a 11 07 6f ?? 00 00 0a 13 04 dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_SPFT_2147948720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.SPFT!MTB"
        threat_id = "2147948720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {63 d1 13 15 11 1a 11 09 91 13 27 11 1a 11 09 11 23 11 27 61 19 11 1c 58 61 11 2c 61 d2 9c}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_PAHN_2147949160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.PAHN!MTB"
        threat_id = "2147949160"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 02 16 02 8e 69 6f ?? 00 00 0a 13 09 20 00 00 00 00 7e}  //weight: 2, accuracy: Low
        $x_1_2 = "RunPassiveProgram" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AMCB_2147949182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AMCB!MTB"
        threat_id = "2147949182"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 06 28 ?? 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 0d 09 08 17 73 ?? 00 00 0a 13 04 02 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 02 6f ?? 00 00 0a dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AXCB_2147949437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AXCB!MTB"
        threat_id = "2147949437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 08 1f 1f 5a 09 58 0e 05 58 61 0a 02 08 09 6f ?? 00 00 0a 13 04 04 03 6f ?? 00 00 0a 59 13 05 11 05}  //weight: 5, accuracy: Low
        $x_2_2 = {05 0e 04 6f ?? 00 00 0a 61 0a 19 8d ?? 00 00 01 0b 0e 04 2c 3f 0e 04 6f ?? 00 00 0a 16 31 35 07 16 0e 04 16 6f ?? 00 00 0a 0e 05 58 20 ff 00 00 00 5f d2 9c 07 17 06 17 62}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_AGDB_2147949832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.AGDB!MTB"
        threat_id = "2147949832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 09 11 06 58 06 19 5f 58 61 0b 02 11 06 11 09 6f ?? 00 00 0a 13 0a 04 03 6f ?? 00 00 0a 59 13 0b 11 0b 13 0c 11 0c 19 31 03 19 13 0c 11 0c 16 2f 03 16 13 0c 19 8d ?? 00 00 01 13 0d 11 0d 16 12 0a 28 ?? 00 00 0a 9c 11 0d 17 12 0a 28 ?? 00 00 0a 9c 11 0d 18 12 0a 28 ?? 00 00 0a 9c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_PureLogStealer_ADEB_2147951005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/PureLogStealer.ADEB!MTB"
        threat_id = "2147951005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "PureLogStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {04 1b 5d 2c 03 03 2b 07 03 20 eb 00 00 00 61 b4 0a 2b 00 06 2a}  //weight: 4, accuracy: High
        $x_2_2 = {11 0a 16 9a 6f ?? ?? 00 0a 13 0c 11 0c 6f ?? ?? 00 0a 72 ?? ?? 00 70 16 28 ?? 00 00 0a 16 fe 01 13 0d 11 0d 2c 22 11 09 6f ?? ?? 00 0a 72 ?? ?? 00 70 16 28 ?? 00 00 0a 16 fe 01 13 0e 11 0e 2c 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

