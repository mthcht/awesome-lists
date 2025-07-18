rule Trojan_MSIL_DarkCloud_ABVN_2147846881_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.ABVN!MTB"
        threat_id = "2147846881"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 16 02 8e 69 6f ?? ?? 00 0a 0a 2b 00 06 2a 19 00 7e ?? 00 00 04 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "BeijingJinJingZheng.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_ABVZ_2147846970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.ABVZ!MTB"
        threat_id = "2147846970"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 21 00 07 09 18 6f ?? ?? 00 0a 1f 10 28 ?? ?? 00 0a d2 13 05 08 11 05 6f ?? ?? 00 0a 00 09 18 58 0d 00 09 07 6f ?? 00 00 0a fe 04 13 06 11 06 2d d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_ABXM_2147847557_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.ABXM!MTB"
        threat_id = "2147847557"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 0d 2b 3f 00 16 13 04 2b 24 00 08 09 11 04 6f ?? 00 00 0a 13 0b 07 11 05 12 0b 28 ?? 00 00 0a 9c 11 05 17 58 13 05 00 11 04 17 58 13 04 11 04 08 6f ?? 00 00 0a fe 04 13 0c 11 0c 2d cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AAFD_2147850720_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AAFD!MTB"
        threat_id = "2147850720"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 02 16 04 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a 1b 00 7e ?? 00 00 04}  //weight: 3, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "Main_Project" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AAGY_2147851538_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AAGY!MTB"
        threat_id = "2147851538"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {04 06 18 28 ?? 00 00 06 7e ?? 00 00 04 06 19 28 ?? 01 00 06 7e ?? 00 00 04 06 28 ?? 01 00 06 0d 7e ?? 00 00 04 09 05 16 05 8e 69 28 ?? 01 00 06 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "reFAdgmmfbFAApAdapAraAmIkmAoAgjlFnhIcbk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AAIH_2147852065_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AAIH!MTB"
        threat_id = "2147852065"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 11 06 07 8e 69 5d 07 11 06 07 8e 69 5d 91 08 11 06 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 07 11 06 17 58 07 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 11 06 15 58 13 06 11 06 16 fe 04 16 fe 01 13 07 11 07 2d ac}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AAIT_2147852330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AAIT!MTB"
        threat_id = "2147852330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 06 8e 69 5d 06 07 06 8e 69 5d 91 11 04 07 1f 16 5d 6f ?? 00 00 0a 61 28 ?? 00 00 0a 06 07 17 58 06 8e 69 5d 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 07 15 58 0b 07 16 fe 04 16 fe 01 13 07 11 07 2d b4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AAOE_2147890071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AAOE!MTB"
        threat_id = "2147890071"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0a 06 18 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 02 7b ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0b 07 03 16 03 8e 69 6f ?? 00 00 0a 0c 2b 00 08 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AAQD_2147892500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AAQD!MTB"
        threat_id = "2147892500"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "apstoneProject2ndYear.Resources.resources" ascii //weight: 2
        $x_1_2 = "4d4a38f9-8dcf-4b2a-b475-5af0c3ab1314" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AAZV_2147899114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AAZV!MTB"
        threat_id = "2147899114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 50 11 00 11 02 59 17 59 11 04 9c}  //weight: 2, accuracy: High
        $x_2_2 = {02 50 11 02 02 50 11 00 11 02 59 17 59 91 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AAZW_2147899854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AAZW!MTB"
        threat_id = "2147899854"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Invoice_FTFAC355.A_" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_BUAA_2147901267_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.BUAA!MTB"
        threat_id = "2147901267"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 04 0e 07 02 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_CRAA_2147901934_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.CRAA!MTB"
        threat_id = "2147901934"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {07 11 09 11 0b 11 0c 61 11 0d 11 07 5d 59 d2 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_DZAA_2147902711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.DZAA!MTB"
        threat_id = "2147902711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 25 26 0a 06 28 ?? 00 00 0a 0b 28 ?? 00 00 06 25 26 28 ?? 00 00 0a 25 26 0c 16 28 ?? 00 00 06 28 ?? 00 00 06 25 26 13 04 11 04 1a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_GWAA_2147904499_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.GWAA!MTB"
        threat_id = "2147904499"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 03 28 ?? 00 00 2b 28 ?? 00 00 2b 16 11 03 8e 69}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_NHAA_2147911066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.NHAA!MTB"
        threat_id = "2147911066"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 1f 09 5d 16 fe 01 13 06 11 06 2c 0c 02 11 05 02 11 05 91 1f 36 61 b4 9c 11 05 17 d6 13 05 11 05 11 04 31 da}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_RP_2147914572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.RP!MTB"
        threat_id = "2147914572"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {26 16 00 20 00 00 00 00 28 35 00 00 06 28 13 00 00 0a 0a 20 04 00 00 00 28 35 00 00 06 28 13 00 00 0a 0b 06 07 28 03 00 00 06 00 2a}  //weight: 1, accuracy: High
        $x_10_2 = {26 16 73 06 00 00 06 0a 06 28 14 00 00 0a 7d 02 00 00 04 06 02 7d 03 00 00 04 06 15 7d 01 00 00 04 06 7c 02 00 00 04 12 00 28 01 00 00 2b 06 7c 02 00 00 04 28 16 00 00 0a 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AQBA_2147924528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AQBA!MTB"
        threat_id = "2147924528"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 00 03 08 09 28 ?? 00 00 06 00 03 04 28 ?? 00 00 06 00 00 07 17 58 0b 07 02 6f ?? 00 00 0a fe 04 13 04 11 04 2d bf}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 0f 01 28 ?? 00 00 0a 9c 25 17 0f 01 28 ?? 00 00 0a 9c 25 18 0f 01 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AWBA_2147924757_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AWBA!MTB"
        threat_id = "2147924757"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {38 d4 00 00 00 08 72 ?? 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 1c 2c ed 17 2c ea 08 72 ?? 02 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 1e 2b 20 16 07 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 28 ?? 00 00 0a 13 06 1c 2c e2 de 32 11 05 2b de 07 2b dd}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AOCA_2147925646_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AOCA!MTB"
        threat_id = "2147925646"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {ff ff ff 11 02 11 02 6f ?? 00 00 0a 11 02 6f ?? 00 00 0a 6f ?? 00 00 0a 13 11 20 02 00 00 00 38 ?? ff ff ff 11 02 72 ab 00 00 70 28 ?? 00 00 0a 6f}  //weight: 3, accuracy: Low
        $x_1_2 = {11 13 11 11 17 73 ?? 00 00 0a 13 05}  //weight: 1, accuracy: Low
        $x_1_3 = {11 05 11 0e 16 11 0e 8e 69 6f ?? 00 00 0a 20}  //weight: 1, accuracy: Low
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_SZJF_2147927610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.SZJF!MTB"
        threat_id = "2147927610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {d1 13 0f 11 1c 11 09 91 13 ?? 11 ?? 11 ?? 11 ?? 11 ?? 61 19 11 1d 58 61 11 35 61 d2 9c}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AKD_2147932609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AKD!MTB"
        threat_id = "2147932609"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 05 06 11 05 91 72 ?? 00 00 70 28 ?? 00 00 0a 59 d2 9c 11 05 17 58 13 05 11 05 06 8e 69}  //weight: 2, accuracy: Low
        $x_1_2 = "oshi.at/VVDd" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AMDG_2147932610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AMDG!MTB"
        threat_id = "2147932610"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 09 03 16 03 8e 69 6f ?? 00 00 0a 08 6f ?? 00 00 0a 13 04 dd 44 00 73 ?? 00 00 0a 0a 06 72 ?? ?? 00 70 28 ?? 00 00 0a 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 73 ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AAB_2147933280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AAB!MTB"
        threat_id = "2147933280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {20 00 01 00 00 14 14 17 8d ?? 00 00 01 25 16 07 6f ?? 00 00 0a a2 28}  //weight: 4, accuracy: Low
        $x_1_2 = {0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 0a 16 0b 2b 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_ACLA_2147933301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.ACLA!MTB"
        threat_id = "2147933301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 04 7e 01 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 7e 02 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 11 04 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 6f ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 06 73 ?? 00 00 0a 13 07 11 07 11 05 16 73 ?? 00 00 0a 13 08 11 08 11 06 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 13 09 de}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_MKZ_2147933524_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.MKZ!MTB"
        threat_id = "2147933524"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 a7 00 00 70 28 17 00 00 0a 13 05 72 d9 00 00 70 28 ?? 00 00 0a 13 06 73 18 00 00 0a 13 07 73 13 00 00 0a 13 08 11 08 11 07 11 05 11 06 6f ?? 00 00 0a 17 73 1a 00 00 0a 13 09 11 09 06 16 06 8e 69 6f 1b 00 00 0a 11 08 6f 15 00 00 0a 13 0a dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AZLA_2147934035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AZLA!MTB"
        threat_id = "2147934035"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 13 04 73 ?? 00 00 0a 13 05 73 ?? 00 00 0a 13 06 11 06 11 05 09 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 07 11 07 08 16 08 8e 69 6f ?? 00 00 0a 17 0b 11 06 6f ?? 00 00 0a 13 08 dd 48}  //weight: 3, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_DLZ_2147934160_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.DLZ!MTB"
        threat_id = "2147934160"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0c 72 c1 01 00 70 28 23 00 00 0a 0d 72 f3 01 00 70 28 ?? 00 00 0a 13 04 73 24 00 00 0a 13 05 73 25 00 00 0a 13 06 11 06 11 05 09 11 04 6f 26 00 00 0a 17 73 ?? 00 00 0a 13 07 2b 16 2b 18 16 2b 18 8e 69 2b 17 17 16 2c 1a 26 2b 1a 2b 1c 13 08 de 70 11 07 2b e6 08 2b e5 08 2b e5 6f ?? 00 00 0a 2b e2 0b 2b e4 11 06 2b e2 6f 29 00 00 0a 2b dd}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_HHL_2147935564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.HHL!MTB"
        threat_id = "2147935564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 06 6f ?? 00 00 0a 0d}  //weight: 6, accuracy: Low
        $x_5_2 = {03 04 58 1f 0a 5d 6b 22 00 00 20 41 5b 26 02 03 04 6f ?? 00 00 0a 0e 04 05 6f ?? 00 00 0a 59 0b 07 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_EABE_2147935738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.EABE!MTB"
        threat_id = "2147935738"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {73 07 00 00 0a 6f 08 00 00 0a 6f 09 00 00 0a 0c 73 0a 00 00 0a 0d 08 09 6f 0b 00 00 0a 09 6f 0c 00 00 0a 0a de 14 09 2c 06 09 6f 0d 00 00 0a dc}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_A_2147936265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.A!MTB"
        threat_id = "2147936265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 ff 00 00 70 28 0b 00 00 0a 13 0a 20 00 00 00 00 7e d7 07 00 04 7b 02 08 00 04 3a c6 ff ff ff 26 20 00 00 00 00 38 bb ff ff ff 73 0c 00 00 0a 13 05 20 03 00 00 00 38 aa ff ff ff 72 19 01 00 70 28 0b 00 00 0a}  //weight: 2, accuracy: High
        $x_2_2 = {8d 10 00 00 01 25 16 d0 13 00 00 01 28 01 00 00 0a a2 28 04 00 00 0a 28 03 00 00 0a 74 02 00 00 1b 73 05 00 00 0a 72 9d 00 00 70 6f 06 00 00 0a}  //weight: 2, accuracy: High
        $x_1_3 = "2373d37f-9d97-4097-b706-3c8581d40cda" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_LVT_2147938398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.LVT!MTB"
        threat_id = "2147938398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 8e 69 17 da 13 04 16 13 05 2b 22 11 05 1e 5d 16 fe 01 13 06 11 06 2c 0f 02 11 05 02 11 05 91 20 ?? 00 00 00 61 b4 9c 11 05 17 d6 13 05 11 05 11 04 31 d8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AIRA_2147939340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AIRA!MTB"
        threat_id = "2147939340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 09 11 09 06 7d ?? 00 00 04 11 09 02 11 07 11 08 6f ?? 00 00 0a 7d ?? 00 00 04 11 09 04 11 09 7b ?? 00 00 04 7b ?? 00 00 04 6f ?? 00 00 0a 59 7d ?? 00 00 04 7e ?? 00 00 04 25 2d 17 26 7e ?? 00 00 04 fe ?? ?? 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 13 0a 11 09 fe ?? ?? 00 00 06 73 ?? 00 00 0a 13 0b 11 09}  //weight: 5, accuracy: Low
        $x_2_2 = {01 25 16 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c 25 17 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c 25 18 02 7c ?? 00 00 04 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_ABTA_2147940913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.ABTA!MTB"
        threat_id = "2147940913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 1a 8d ?? 00 00 01 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 2b 3e 8d ?? 00 00 01 2b 3b 16 2b 3c 2b 15 2b 3c 2b 3e 2b 40 2b 42 2b 44 2b 46 59 6f ?? 00 00 0a 58 13 07 1c 2c 09 11 07 11 04 17 2c f3 32 df 11 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_ARTA_2147941252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.ARTA!MTB"
        threat_id = "2147941252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 8e 69 1a 2f 04 16 0b de 73 20 ?? ?? 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0c 20 ?? ?? 00 00 28 ?? 00 00 06 28 ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 05 03 20 ?? ?? 00 00 28 ?? 00 00 06 11 05 06 16 06 8e 69 6f ?? 00 00 0a 6f ?? 00 00 06 de 0c}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AXTA_2147941415_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AXTA!MTB"
        threat_id = "2147941415"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 1a 8d ?? 00 00 01 0d 08 09 16 09 8e 69 6f ?? 00 00 0a 26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 2b 3e 8d ?? 00 00 01 2b 3b 16 2b 3c 2b 15 2b 3c 2b 3e 2b 40 2b 42 2b 44 2b 46 59 6f ?? 00 00 0a 58 13 07 1c 2c 09 11 07 11 04 17 2c f3 32 df 72 ?? ?? 00 70 11 06 03 28 ?? 00 00 06 17 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AKUA_2147941704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AKUA!MTB"
        threat_id = "2147941704"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 08 6f ?? 00 00 0a 11 04 09 6f ?? 00 00 0a 73 ?? 00 00 0a 13 05 11 05 11 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 2b 1c 2b 1e 16 2b 1e 8e 69 2b 1d 2b 22 2b 24 2b 29 2b 2a 2b 2c 6f ?? 00 00 06 17 0b de 6a 11 06 2b e0 06 2b df 06 2b df 6f ?? 00 00 0a 2b dc 11 06 2b da 6f ?? 00 00 0a 2b d5 03 2b d4 11 05 2b d2 6f ?? 00 00 0a 2b cd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AOVA_2147942377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AOVA!MTB"
        threat_id = "2147942377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 2b 32 2b 34 16 2b 34 8e 69 2b 33 2b 38 2b 3a 2b 3f 2b 41 2b 46 72 ?? ?? 00 70 03 11 06 28 ?? 00 00 06 05 72 ?? ?? 00 70 6f ?? 00 00 0a 17 0b dd ?? 00 00 00 11 05 2b ca 06 2b c9 06 2b c9 6f ?? 00 00 0a 2b c6 11 05 2b c4 6f ?? 00 00 0a 2b bf 11 04 2b bd 6f ?? 00 00 0a 2b b8 13 06 2b b6}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AQVA_2147942431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AQVA!MTB"
        threat_id = "2147942431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0c 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 02 7b ?? 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 06 16 06 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 13 06 03 72 ?? ?? 00 70 11 06 6f ?? 00 00 06 17 0b dd}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_MRE_2147942475_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.MRE!MTB"
        threat_id = "2147942475"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 02 7b 06 00 00 04 6f ?? 00 00 0a 08 6f ?? 00 00 0a 0d 73 2d 00 00 0a 13 04 11 04 09 17 73 2e 00 00 0a 13 05 2b 32 2b 34 16 2b 34 8e 69 2b 33 2b 38 2b 3a 2b 3f 2b 41 2b 46 11 06 03 72 3e 02 00 70 28 ?? 00 00 06 05 72 62 02 00 70 6f ?? 00 00 0a 17 0b dd 80 00 00 00 11 05 2b ca 06 2b c9 06 2b c9 6f ?? 00 00 0a 2b c6 11 05 2b c4 6f ?? 00 00 0a 2b bf 11 04 2b bd 6f ?? 00 00 0a 2b b8 13 06 2b b6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AFWA_2147943192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AFWA!MTB"
        threat_id = "2147943192"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 11 11 16 6f ?? 00 00 0a 13 17 73 ?? 00 00 0a 13 18 11 18 72 ?? ?? 00 70 11 11 11 16 73 ?? 00 00 0a 6f ?? 00 00 0a 11 18 72 ?? ?? 00 70 28 ?? 00 00 0a 8c ?? 00 00 01 6f ?? 00 00 0a 11 18 72 ?? ?? 00 70 72 ?? ?? 00 70 11 09 1e 5d 13 1f 12 1f 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 11 18 72 ?? ?? 00 70 11 10 8c ?? 00 00 01 6f ?? 00 00 0a 11 0e 11 18 6f ?? 00 00 0a 12 17 28 ?? 00 00 0a 13 19 12 17 28 ?? 00 00 0a 13 1a 12 17 28 ?? 00 00 0a 13 1b 1b 8d ?? 00 00 01 25 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AIXA_2147944420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AIXA!MTB"
        threat_id = "2147944420"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 00 11 03 02 11 03 91 03 11 03 11 01 5d 6f ?? 00 00 0a 61 d2 9c 20}  //weight: 4, accuracy: Low
        $x_2_2 = {11 03 17 58 13 03 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_SKC_2147945411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.SKC!MTB"
        threat_id = "2147945411"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 08 20 00 96 00 00 16 17 72 7f 00 00 70 22 00 00 80 3f 17 17 72 1d 01 00 70 20 00 01 00 00 16 72 2d 02 00 70 28 07 00 00 06 00 72 05 17 00 70 13 07 11 07 72 21 17 00 70 6f 1d 00 00 0a 13 08 11 08 2c 0e}  //weight: 1, accuracy: High
        $x_1_2 = "$C8F7E6D5-A4B3-9281-7654-098765432CBA" ascii //weight: 1
        $x_1_3 = "UPA_HELPER.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_AB_2147945968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.AB!MTB"
        threat_id = "2147945968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 13 06 07 09 8e 69 11 06 16 11 06 8e 69 28 54 04 00 0a 00 11 05 11 06 16 11 06 8e 69 6f}  //weight: 2, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_DarkCloud_GTD_2147946777_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/DarkCloud.GTD!MTB"
        threat_id = "2147946777"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "DarkCloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b 00 07 03 6f ?? 00 00 0a 00 07 04 6f ?? 00 00 0a 00 07 17 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 73 ?? ?? ?? ?? 0c 08 07 6f ?? 00 00 0a 17 73 ?? ?? ?? ?? 0d 00 09 06 16 06 8e 69 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 08 6f ?? 00 00 0a 13 04 de 28}  //weight: 10, accuracy: Low
        $x_1_2 = "Confuser.Core" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

