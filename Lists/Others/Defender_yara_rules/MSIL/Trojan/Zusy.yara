rule Trojan_MSIL_Zusy_PSOM_2147848876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSOM!MTB"
        threat_id = "2147848876"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 6b 11 00 70 28 ?? ?? ?? 0a 0a 06 6f ?? ?? ?? 0a 0b 07 6f ?? ?? ?? 0a 0c 7e ?? ?? ?? 0a 0d 08 73 ?? ?? ?? 0a 13 04 00 11 04 6f ?? ?? ?? 0a 0d 00 de 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSPO_2147849358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSPO!MTB"
        threat_id = "2147849358"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 08 74 1f 00 00 01 74 11 00 00 01 20 f7 01 00 00 20 df 01 00 00 28 ?? ?? ?? 2b 14 06 74 10 00 00 01 20 6e 01 00 00 20 69 01 00 00 28 ?? ?? ?? 2b 20 89 00 00 00 20 ac 00 00 00 28 ?? ?? ?? 2b 13 05 11 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EN_2147849810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EN!MTB"
        threat_id = "2147849810"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fa 01 33 00 16 00 00 01 00 00 00 33 00 00 00 16 00 00 00 15 00 00 00 18 00 00 00 02 00 00 00 3b 00 00 00 0e 00 00 00 05 00 00 00 02 00 00 00 01 00 00 00 04}  //weight: 1, accuracy: High
        $x_1_2 = "Project.Rummage.exe" ascii //weight: 1
        $x_1_3 = "GetSubKeyNames" ascii //weight: 1
        $x_1_4 = "BitConverter" ascii //weight: 1
        $x_1_5 = "WebRequest" ascii //weight: 1
        $x_1_6 = "ProxyUse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSRR_2147850754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSRR!MTB"
        threat_id = "2147850754"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 06 72 bb 00 00 70 6f 0b 00 00 0a 17 8d 0d 00 00 01 13 07 11 07 16 1f 0a 9d 11 07 6f 0c 00 00 0a 0b 06 6f 0d 00 00 0a 00 16 8d 0e 00 00 01 0c 00 07 13 08 16 13 09 2b 43}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSSI_2147851036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSSI!MTB"
        threat_id = "2147851036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 18 00 00 0a 6f ?? 00 00 0a 07 72 c9 00 00 70 73 1a 00 00 0a 08 6f ?? 00 00 0a 06 7b 05 00 00 04 6f ?? 00 00 0a 26 08 28 ?? 00 00 0a 2d 57}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSSU_2147851382_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSSU!MTB"
        threat_id = "2147851382"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 25 06 72 75 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 73 23 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 7d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AZU_2147851741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AZU!MTB"
        threat_id = "2147851741"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {14 0a 16 0c 16 13 05 2b 0c 00 08 17 58 0c 00 11 05 17 58 13 05 11 05 ?? ?? ?? ?? ?? fe 04 13 06 11 06 2d e5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NY_2147851878_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NY!MTB"
        threat_id = "2147851878"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 20 31 57 57 35 5a 20 ?? ?? ?? 13 61 2b c9 00 20 ?? ?? ?? ec 2b c1 7e ?? ?? ?? 04 28 ?? ?? ?? 06 0a 07 20 ?? ?? ?? b2 5a 20 ?? ?? ?? 9f 61 2b a7 07 20 ?? ?? ?? e4 5a 20 ?? ?? ?? fa 61 2b 98}  //weight: 5, accuracy: Low
        $x_1_2 = "MemberDefRidsAllocated.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTN_2147851888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTN!MTB"
        threat_id = "2147851888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 11 00 00 70 72 06 01 00 70 73 11 00 00 0a 72 14 01 00 70 28 13 00 00 0a 72 52 01 00 70 28 14 00 00 0a 28 01 00 00 06 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTO_2147851889_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTO!MTB"
        threat_id = "2147851889"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 00 07 06 28 ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 26 72 f6 01 00 70 28 ?? 00 00 0a 00 00 de 1b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTS_2147851955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTS!MTB"
        threat_id = "2147851955"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 99 02 00 70 28 ?? 00 00 0a 06 72 a7 02 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 06 28 ?? 00 00 0a 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTU_2147852005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTU!MTB"
        threat_id = "2147852005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7d 06 00 00 04 06 03 7d 05 00 00 04 06 15 7d 03 00 00 04 06 7c 04 00 00 04 12 00 28 01 00 00 2b 06 7c 04 00 00 04 28 10 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTX_2147852144_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTX!MTB"
        threat_id = "2147852144"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 13 00 00 0a 25 6f ?? 00 00 0a 72 01 00 00 70 72 1b 00 00 70 6f ?? 00 00 0a 02 0a 03 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NZS_2147852199_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NZS!MTB"
        threat_id = "2147852199"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 1e 17 d6 13 1e 11 09 6f ?? ?? ?? 0a 13 0a 11 1e 1b 3e ?? ?? ?? 00 11 0b 2c 3e 11 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 2c 1b 16 13 0b 11 0a 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 13 17 38 ?? ?? ?? 00}  //weight: 5, accuracy: Low
        $x_1_2 = "M8Y Data Mail 2 CSV" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSTZ_2147852256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSTZ!MTB"
        threat_id = "2147852256"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 12 00 00 0a 25 72 01 00 00 70 72 49 00 00 70 6f ?? 00 00 0a 72 65 00 00 70 72 ab 00 00 70 6f ?? 00 00 0a 72 ab 00 00 70 28 ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSUB_2147852361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSUB!MTB"
        threat_id = "2147852361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 12 00 00 0a 72 01 00 00 70 72 47 00 00 70 6f ?? 00 00 0a 72 47 00 00 70 28 ?? 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSUG_2147852496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSUG!MTB"
        threat_id = "2147852496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 28 1c 00 00 0a 72 91 00 00 70 73 1d 00 00 0a 13 09 11 08 72 b3 00 00 70 11 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GP_2147888821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GP!MTB"
        threat_id = "2147888821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 1d 00 00 01 25 d0 ae 00 00 04 28 20 00 00 0a 6f ?? 00 00 0a 06 07 6f ?? 00 00 0a 17 73 81 00 00 0a 25 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_RDC_2147888828_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.RDC!MTB"
        threat_id = "2147888828"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7759b98a-dd53-478f-b0c1-0dd79a5f46a5" ascii //weight: 1
        $x_1_2 = "loader" ascii //weight: 1
        $x_1_3 = "ComputeHash" ascii //weight: 1
        $x_1_4 = "cant deobfuscate :))" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSWM_2147889431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSWM!MTB"
        threat_id = "2147889431"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {12 00 28 1a 00 00 0a 7d 20 00 00 04 12 00 15 7d 1f 00 00 04 12 00 7c 20 00 00 04 12 00 28 03 00 00 2b 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSWN_2147889554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSWN!MTB"
        threat_id = "2147889554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "QjAIgwSe" ascii //weight: 2
        $x_2_2 = "zkvVhsF" ascii //weight: 2
        $x_1_3 = "DebuggingModes" ascii //weight: 1
        $x_1_4 = "GetResponseStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSWQ_2147890090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSWQ!MTB"
        threat_id = "2147890090"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {19 73 14 00 00 0a 73 15 00 00 0a 13 07 de 19 6f ?? 00 00 0a 72 65 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a dd f6 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSXG_2147890472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSXG!MTB"
        threat_id = "2147890472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 73 18 00 00 0a 13 04 11 04 72 45 02 00 70 72 f8 02 00 70 6f ?? 00 00 0a 00 72 f8 02 00 70 28 ?? 00 00 0a 26 02 28 ?? 00 00 06 00 00 15 28 ?? 00 00 0a 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSXI_2147890550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSXI!MTB"
        threat_id = "2147890550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 1c 00 00 0a 26 02 28 04 00 00 06 15 28 1b 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NSZ_2147891686_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NSZ!MTB"
        threat_id = "2147891686"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {20 07 00 00 00 28 ?? ?? ?? 06 3a ?? ?? ?? ff 26 06 20 ?? ?? ?? 00 0d 12 03 6f ?? ?? ?? 06 20 ?? ?? ?? 00 38 ?? ?? ?? ff 00 73 ?? ?? ?? 06 0a 16 28 ?? ?? ?? 06 39 ?? ?? ?? 00 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "doorinbook_847214" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NS_2147891690_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NS!MTB"
        threat_id = "2147891690"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 1f 10 5a 13 04 1f 10 8d ?? 00 00 01 13 05 03 11 04 11 05 16 1f 10 28 ?? 00 00 0a 06 11 05 16 11 05 8e 69 6f ?? 00 00 0a 16 08 09 1f 10 5a 1f 10}  //weight: 5, accuracy: Low
        $x_1_2 = "DPApp.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMAC_2147892943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMAC!MTB"
        threat_id = "2147892943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 08 11 04 03 11 04 91 07 61 06 09 91 61 d2 9c 09 04 6f ?? 00 00 0a 17 59 fe 01 13 05 11 05 2c 04 16 0d 2b 04 09 17 58 0d 00 11 04 17 58 13 04 11 04 03 8e 69 fe 04 13 06 11 06 2d c3}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AZ_2147893304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AZ!MTB"
        threat_id = "2147893304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 08 11 05 11 07 11 08 11 08 8e 69 16 28 ?? 01 00 06 2d 02 1c 2a 11 05 16 e0 28 ?? 01 00 0a 7e ?? 01 00 04 11 06 11 07 16 16 e0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_KA_2147896272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.KA!MTB"
        threat_id = "2147896272"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {07 08 02 08 1a 58 91 06 d2 61 d2 9c 06 17 62 06 1f 1f 63 60 0a 08 17 58 0c 08 07 8e 69 32 e1}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMBC_2147896567_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMBC!MTB"
        threat_id = "2147896567"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Svdrd.exe" ascii //weight: 1
        $x_1_2 = "Svdrd.Resources.resources" ascii //weight: 1
        $x_1_3 = "AesManaged" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "DownloadString" ascii //weight: 1
        $x_1_6 = "bmV3YnRyLmV4ZQ==" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTCH_2147897001_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTCH!MTB"
        threat_id = "2147897001"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 72 97 00 00 70 0a 02 06 28 ?? 00 00 06 00 72 d5 00 00 70 0b 02 07 28 ?? 00 00 06 00 00 de 1b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSZQ_2147897054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSZQ!MTB"
        threat_id = "2147897054"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 2a 00 28 ?? 00 00 06 73 01 00 00 0a 13 07 20 00 00 00 00 7e e7 08 00 04 7b 38 09 00 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTAU_2147897057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTAU!MTB"
        threat_id = "2147897057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 59 00 00 70 a2 28 14 00 00 0a 18 28 01 00 00 2b 28 16 00 00 0a 0a 06 1f 0a 8d 23 00 00 01 25 16 7e 12 00 00 0a 6f 13 00 00 0a a2 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSSZ_2147897154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSSZ!MTB"
        threat_id = "2147897154"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 26 04 00 04 20 92 c2 66 06 28 ?? 06 00 06 28 ?? 06 00 06 0a 06 12 01 12 02 28 ?? 04 00 06 2c 12 7e f2 07 00 04 07 08 28 ?? 07 00 06 26 dd a7 01 00 00 de 03}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTCQ_2147897341_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTCQ!MTB"
        threat_id = "2147897341"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 6f 32 00 00 06 6f 6a 00 00 0a 00 02 72 df 00 00 70 6f 60 00 00 0a 00 02 72 eb 00 00 70 6f 6b 00 00 0a 00 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PSPS_2147897590_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PSPS!MTB"
        threat_id = "2147897590"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 7b 06 00 00 04 04 6f ?? ?? ?? 0a 0b 73 ?? ?? ?? 0a 25 07 6f ?? ?? ?? 0a 72 43 01 00 70 6f 51 00 00 0a 6f 52 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTDX_2147898912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTDX!MTB"
        threat_id = "2147898912"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 75 00 00 0a 0c 00 03 28 ?? 00 00 0a 73 77 00 00 0a 13 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NZ_2147899461_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NZ!MTB"
        threat_id = "2147899461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 68 00 00 0a 02 6f ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 0a 73 ?? 00 00 0a 06 6f ?? 00 00 0a 28 23 00 00 06}  //weight: 5, accuracy: Low
        $x_1_2 = "MelonSpoofer_b2.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NZ_2147899461_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NZ!MTB"
        threat_id = "2147899461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 28 06 00 00 06 75 ?? ?? ?? 1b 28 ?? ?? ?? 0a 13 04 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff dd ?? ?? ?? ff 20 ?? ?? ?? 00 7e ?? ?? ?? 04 7b ?? ?? ?? 04 3a ?? ?? ?? ff 26 20 ?? ?? ?? 00 38 ?? ?? ?? ff}  //weight: 5, accuracy: Low
        $x_1_2 = "Mkwimscxva.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NZ_2147899461_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NZ!MTB"
        threat_id = "2147899461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {8d 1b 00 00 01 25 16 72 01 00 00 70 a2 25 17 72 41 00 00 70 a2 25 18 72 7d 00 00 70 a2 13 04 00 11 04 13 0a 16}  //weight: 3, accuracy: High
        $x_2_2 = {28 26 00 00 0a 7e 07 00 00 04 6f 27 00 00 0a 0a 28 26 00 00 0a 7e 06 00 00 04 6f 27 00 00 0a 0b 02 28 28 00 00 0a 0c 16 13 04}  //weight: 2, accuracy: High
        $x_1_3 = "Piano_In[sta/ler64bit@gmail#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NZ_2147899461_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NZ!MTB"
        threat_id = "2147899461"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {03 0a 72 01 00 00 70 06 72 45 00 00 70 28 17 00 00 0a 0b 73 18 00 00 0a 25 72 49 00 00 70 6f ?? 00 00 0a 00 25 72 67 00 00 70 07 72 7d 00 00 70 28 17 00 00 0a 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 17 6f ?? 00 00 0a 00 25 16 6f ?? 00 00 0a 00 25 17}  //weight: 3, accuracy: Low
        $x_2_2 = {20 10 27 00 00 28 ?? 00 00 0a 00 28 ?? 00 00 0a 02 7b 02 00 00 04 6f 2e 00 00 0a 0a 72 33 01 00 70 28 ?? 00 00 0a 0b 07}  //weight: 2, accuracy: Low
        $x_1_3 = "WindowsFormsApp47.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMBH_2147899966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMBH!MTB"
        threat_id = "2147899966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1e 63 d1 13 12 11 14 11 09 91 13 20 11 14 11 09 11 20 11 24 61 11 1c 19 58 61 11 35 61 d2 9c 11 09 17 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AF_2147900092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AF!MTB"
        threat_id = "2147900092"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 25 25 02 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 13 ?? 6f ?? 00 00 0a 14 26 28}  //weight: 4, accuracy: Low
        $x_4_2 = {0d 25 25 02 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 26 6f ?? 00 00 0a 14 26 09 72}  //weight: 4, accuracy: Low
        $x_4_3 = {0d 25 25 02 28 ?? 00 00 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 06 13 ?? 6f ?? 00 00 0a 14 26 28}  //weight: 4, accuracy: Low
        $x_1_4 = "wtools.io/code/dl" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Zusy_PTFH_2147900531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTFH!MTB"
        threat_id = "2147900531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 9c 00 00 0a 17 73 3c 00 00 0a 25 02 16 02 8e 69 6f 9d 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_KAB_2147900781_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.KAB!MTB"
        threat_id = "2147900781"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {a2 fd 16 f9 d4 15 f2 75 f4 2f 70 63 4f e9 b1 02 00 47 9f d1 ab 3e 73 a1 ba 5e 22}  //weight: 1, accuracy: High
        $x_1_2 = {9e fc 6b 19 f2 0a 6c f8 eb 33 23 71 c9 69 6b 90 91 63 c3 d5 d7 e7 63 f9}  //weight: 1, accuracy: High
        $x_1_3 = "aedrfbix" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTGO_2147900968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTGO!MTB"
        threat_id = "2147900968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {59 07 8e 69 59 28 ?? 00 00 2b 28 ?? 00 00 2b 02 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_CCGX_2147901017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.CCGX!MTB"
        threat_id = "2147901017"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 16 11 17 9a 13 18 00 11 18 28 ?? 00 00 0a 13 19 11 19 2c 14 09 6f ?? 00 00 0a 11 18 73 ?? ?? ?? ?? 6f ?? 00 00 0a 00 00 00 de 10 25 28 ?? 00 00 0a 13 1a 00 28 ?? 00 00 0a de 00 00 00 11 17 17 d6 13 17 11 17 11 16 8e 69 fe 04 13 1b 11 1b 2d ae}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_RDF_2147901332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.RDF!MTB"
        threat_id = "2147901332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "niggerspoofa" ascii //weight: 1
        $x_1_2 = "eacdriv" ascii //weight: 1
        $x_1_3 = "guna2Button7_Click" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GMX_2147901404_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GMX!MTB"
        threat_id = "2147901404"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ewqeuhiwquiye32uiy43289734712984y3ui2rekjhfdskm" wide //weight: 1
        $x_1_2 = "stormss.xyz/api" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GMY_2147901678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GMY!MTB"
        threat_id = "2147901678"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 11 0a 20 ?? ?? ?? ?? 58 61 16 58 38 ?? ?? ?? ?? 08 6f ?? ?? ?? 06 2c 08 20 ?? ?? ?? ?? 25 2b 06 20 ?? ?? ?? ?? 25 26 11 0a 20 ?? ?? ?? ?? 58 61 16 58}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTHM_2147901857_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTHM!MTB"
        threat_id = "2147901857"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 78 00 00 0a 17 59 28 ?? 00 00 0a 16 7e 37 00 00 04 02 1a 28 ?? 00 00 0a 11 05 0d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPDD_2147901980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPDD!MTB"
        threat_id = "2147901980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 03 00 00 04 6f ?? ?? ?? 0a 05 0e 08 02 8e 69 6f ?? ?? ?? 0a 0a 06 0b 2b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTHT_2147902042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTHT!MTB"
        threat_id = "2147902042"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 2c 28 06 28 ?? 00 00 0a 6f 15 00 00 0a 28 ?? 00 00 2b 6f 17 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTHX_2147902142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTHX!MTB"
        threat_id = "2147902142"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f fa 00 00 0a 13 04 02 0d 11 04 09 16 09 8e b7 6f f9 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPYY_2147902223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPYY!MTB"
        threat_id = "2147902223"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 08 06 6f ?? ?? ?? 0a 5d 6f ?? ?? ?? 0a 05 58 0d 07 02 08 6f ?? ?? ?? 0a 09 61 d1 6f ?? ?? ?? 0a 26 08 17 58 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTHZ_2147902241_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTHZ!MTB"
        threat_id = "2147902241"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {38 08 f5 ff ff 28 ?? 00 00 0a fe 0c 01 00 6f 29 00 00 0a 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTIB_2147902242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTIB!MTB"
        threat_id = "2147902242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 45 00 00 70 28 ?? 00 00 0a 6f 12 00 00 0a 6f 12 00 00 0a 6f 13 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GPA_2147902465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GPA!MTB"
        threat_id = "2147902465"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 0a 05 58 0e 04 5d 13 04 08 02 09 6f ?? 00 00 0a 11 ?? 61 d1 6f ?? 00 00 0a 26 00 09 17 58 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_LA_2147902547_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.LA!MTB"
        threat_id = "2147902547"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e 9b 08 ?? ?? 0e 06 17 59 95 58 0e 05}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NA_2147902552_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NA!MTB"
        threat_id = "2147902552"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "//vegax.gg/windows/ui_ver.php" ascii //weight: 5
        $x_1_2 = "VegaX\\VegaX\\obj\\Release\\Vega X.pdb" ascii //weight: 1
        $x_1_3 = "HKEY_CURRENT_USER\\Software\\VegaX" ascii //weight: 1
        $x_1_4 = "/Vega X;component/spawnablewindows/injectcode.xaml" ascii //weight: 1
        $x_1_5 = "autoexec\\vegaxfpsunlocker.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTIG_2147902596_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTIG!MTB"
        threat_id = "2147902596"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 55 20 00 70 07 72 8f 20 00 70 6f 4d 00 00 0a 28 ?? 00 00 0a 00 73 84 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTIH_2147902597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTIH!MTB"
        threat_id = "2147902597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 66 08 00 00 28 ?? 00 00 0a 00 72 01 00 00 70 28 ?? 00 00 06 28 ?? 00 00 0a 0a 06 0b 2b 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTII_2147902639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTII!MTB"
        threat_id = "2147902639"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 0e 00 28 ?? 00 00 0a 72 b4 04 00 70 6f 4e 00 00 0a 13 0f 11 07 11 0f 8e 69 6a 6f 4f 00 00 0a 00 11 07 6f 50 00 00 0a 13 10 11 10 11 0f 16 11 0f 8e 69 6f 51 00 00 0a 00 17 28 ?? 00 00 0a 00 11 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMBE_2147903242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMBE!MTB"
        threat_id = "2147903242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 08 12 08 28 ?? 00 00 0a 28 ?? 00 00 0a 16 09 06 1a 28 ?? 00 00 0a 00 06 1a 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NC_2147903264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NC!MTB"
        threat_id = "2147903264"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 d5 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_ND_2147903265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.ND!MTB"
        threat_id = "2147903265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 e8 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NF_2147903271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NF!MTB"
        threat_id = "2147903271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 03 02 4b 03 04 61 05 61 58 0e 07 0e 04 95 58 7e ?? 08 00 04 0e 06 17 59 95 58 0e 05 28 de 0d 00 06 58 54 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTJB_2147903332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTJB!MTB"
        threat_id = "2147903332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 25 00 00 0a 15 16 28 ?? 00 00 0a 0b 02 28 ?? 00 00 0a 07 17 9a 6f 27 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPDP_2147904014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPDP!MTB"
        threat_id = "2147904014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 03 00 00 04 6f ?? ?? ?? 0a 05 0e 07 0e 04 8e 69 6f ?? ?? ?? 0a 0a 06 0b 2b 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMMB_2147904076_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMMB!MTB"
        threat_id = "2147904076"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a fe 09 00 00 7b ?? 00 00 04 fe 09 00 00 7b ?? 00 00 04 6f ?? 00 00 0a fe 09 01 00 20 ?? ?? ?? ?? fe 09 01 00 8e 69 6f ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "Select * from Win32_CacheMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPCZ_2147904269_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPCZ!MTB"
        threat_id = "2147904269"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 72 01 00 00 70 6f ?? ?? ?? 0a 0c 08 17 8d 15 00 00 01 25 16 1f 0a 9d 6f ?? ?? ?? 0a 0d 28 ?? ?? ?? 0a 13 04 00 09 13 08 16 13 09 38 b3 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NG_2147904509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NG!MTB"
        threat_id = "2147904509"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {61 60 0a 00 09 17 58 0d 09 02 6f 19 00 00 0a fe 04 13 04 11 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PTIA_2147905357_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PTIA!MTB"
        threat_id = "2147905357"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {58 11 04 16 08 28 ?? 00 00 0a 28 ?? 00 00 0a 11 04 16 11 04 8e 69 6f 54 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_RDG_2147905613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.RDG!MTB"
        threat_id = "2147905613"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 03 00 00 04 6f 36 00 00 0a 02 0e 04 03 8e 69 6f 37 00 00 0a 0a 06 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GPAE_2147905957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GPAE!MTB"
        threat_id = "2147905957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_2 = "\\AppData\\Local\\Google\\Chrome\\User Data\\Local State" ascii //weight: 1
        $x_1_3 = "\\AppData\\Roaming\\Microsoft\\protects.zip" ascii //weight: 1
        $x_1_4 = "sam.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_ARAA_2147906263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.ARAA!MTB"
        threat_id = "2147906263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\AutoTorIP\\obj\\Debug\\SecurSocks.pdb" ascii //weight: 2
        $x_2_2 = "$3158fb64-4f13-4bf9-a10d-cf776a49140f" ascii //weight: 2
        $x_2_3 = "ServerStorage" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GPC_2147907835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GPC!MTB"
        threat_id = "2147907835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 03 00 00 04 6f ?? 00 00 0a 02 0e 04 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 07 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GZX_2147909114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GZX!MTB"
        threat_id = "2147909114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 11 0d 6f ?? ?? ?? 0a 13 0c 02 09 11 09 11 0c 28 ?? ?? ?? 06 13 0d 16 13 11 2b 1b 00 11 0e 11 11 8f ?? ?? ?? 01 25 47 11 0d 11 11 91 61 d2 52 00 11 11 17 58 13 11 11 11 11 0e 8e 69 fe 04 13 12 11 12 2d d7}  //weight: 10, accuracy: Low
        $x_1_2 = "Pillager.dll" ascii //weight: 1
        $x_1_3 = "TripleDESCryptoServiceProvider" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GZX_2147909114_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GZX!MTB"
        threat_id = "2147909114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "You've been hacked by Lord Farquaad" ascii //weight: 1
        $x_1_2 = "EncryptedLog.txt" ascii //weight: 1
        $x_1_3 = "KeyAndIV.txt" ascii //weight: 1
        $x_1_4 = "Seven_ProcessedByFody" ascii //weight: 1
        $x_1_5 = "Seven.dll" ascii //weight: 1
        $x_1_6 = "LogDecrypted" ascii //weight: 1
        $x_1_7 = "LogEncrypted" ascii //weight: 1
        $x_1_8 = "Open420Port" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_MSIL_Zusy_CCIB_2147909285_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.CCIB!MTB"
        threat_id = "2147909285"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LogDecrypted" ascii //weight: 1
        $x_1_2 = "LogEncrypted" ascii //weight: 1
        $x_1_3 = "EncryptFileSystem" ascii //weight: 1
        $x_1_4 = "DeleteAllDriveContents" ascii //weight: 1
        $x_1_5 = "EncryptDriveContents" ascii //weight: 1
        $x_1_6 = "Open420Port" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPUF_2147912426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPUF!MTB"
        threat_id = "2147912426"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 08 08 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 0d 02 73 18 00 00 0a 13 04 00 11 04 09 16 73 19 00 00 0a 13 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_MA_2147913697_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.MA!MTB"
        threat_id = "2147913697"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {fe 0c 00 00 7e 01 00 00 04 73 23 00 00 0a fe 0c 02 00 6f 24 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EC_2147914331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EC!MTB"
        threat_id = "2147914331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {25 16 1f 2d 9d 6f a4 00 00 0a 0c 08 16 9a 28 16 00 00 0a 08 17 9a 08 18 9a}  //weight: 5, accuracy: High
        $x_2_2 = "CensoIBGE.RemoveCadastro.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EC_2147914331_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EC!MTB"
        threat_id = "2147914331"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "unknownspf_loader" ascii //weight: 5
        $x_5_2 = "ahdkakhd2oiauzd9a8du0a2dua209dua289dua2980dua2908dua29dua92dua9du9a2duz" ascii //weight: 5
        $x_1_3 = "del /s /f /q C:\\Windows\\Prefetch" ascii //weight: 1
        $x_1_4 = "NTEuODkuNy4zMw==" ascii //weight: 1
        $x_1_5 = "deactivation.php?hash=" ascii //weight: 1
        $x_1_6 = "activation.php?code=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMAA_2147915079_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMAA!MTB"
        threat_id = "2147915079"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 0c 08 07 17 73 ?? 00 00 0a 0d 28 [0-30] 00 00 0a 09 6f ?? 00 00 0a 08 6f ?? 00 00 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SSA_2147917073_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SSA!MTB"
        threat_id = "2147917073"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://103.116.105.90/kyuc1/" ascii //weight: 1
        $x_1_2 = "so2game_lite.exe" ascii //weight: 1
        $x_1_3 = "Autoupdate_bak.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NK_2147917445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NK!MTB"
        threat_id = "2147917445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 00 17 64 13 00 ?? ?? 00 00 00 11 01 11 00 11 04 17 59 5f 59 13 01}  //weight: 2, accuracy: Low
        $x_2_2 = {11 03 11 07 d2 6e 1e 11 06 5a 1f 3f 5f 62 60 13 03}  //weight: 2, accuracy: High
        $x_1_3 = "Tyrone.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NK_2147917445_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NK!MTB"
        threat_id = "2147917445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "2a9d7962-3566-3296-9897-138233125171" ascii //weight: 2
        $x_1_2 = "set_UseShellExecute" ascii //weight: 1
        $x_1_3 = "Koi.Properties" ascii //weight: 1
        $x_1_4 = "VirtualAllocEx" ascii //weight: 1
        $x_1_5 = "settings\\shop\\type.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNH_2147919603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNH!MTB"
        threat_id = "2147919603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 5f 44 65 6c 65 67 61 74 65 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 5f 44 65 6c 65 67 61 74 65 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 5f 44 65 6c 65 67 61 74 65}  //weight: 3, accuracy: High
        $x_1_2 = {00 45 78 65 63 75 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5a 77 55 6e 6d 61 70 56 69 65 77 4f 66 53 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 43 72 65 61 74 65 50 72 6f 63 65 73 73 41 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 0b 6e 00 74 00 64 00 6c 00 6c 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNF_2147919617_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNF!MTB"
        threat_id = "2147919617"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0c 83 45 31 c0 49 01 c9 43 8a 34 02 40 84 f6 74}  //weight: 2, accuracy: High
        $x_1_2 = {47 65 74 50 72 6f 63 41 48 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 41 64 64 72 65 73 73}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNI_2147919982_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNI!MTB"
        threat_id = "2147919982"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "1D1CC35EA61331C5A85D2A960611153E37A62DCD916269D6E3B5A0DAC2EF3824" ascii //weight: 2
        $x_1_2 = {2e 65 78 65 00 46 69 6e 61 6c 55 6e 63 6f 6d 70 72 65 73 73 65 64 53 69 7a 65 00 52 74 6c 47 65 74 43 6f 6d 70 72 65 73 73 69 6f 6e 57 6f 72 6b 53 70 61 63 65 53 69 7a 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 79 73 74 65 6d 2e 4e 65 74 00 53 6f 63 6b 65 74 00 73 6f 63 6b 65 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNK_2147920096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNK!MTB"
        threat_id = "2147920096"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "YW1zaS5kbGw=" ascii //weight: 5
        $x_5_2 = "QW1zaVNjYW5CdWZmZXI=" ascii //weight: 5
        $x_1_3 = {00 47 65 74 50 72 6f 63 41 64 64 72 65 73 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SLZ_2147921863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SLZ!MTB"
        threat_id = "2147921863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 0b 00 00 0a 72 01 00 00 70 28 0c 00 00 0a 6f ?? ?? ?? 0a 13 04 12 04 28 0e 00 00 0a 2d 43 02 16 7d ?? ?? ?? 04 02 11 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_BB_2147922681_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.BB!MTB"
        threat_id = "2147922681"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 09 1e 38 ?? ff ff ff 11 09 72 ?? 01 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 09 1f 09 38 ?? ff ff ff 28 ?? 00 00 0a 11 07 28 ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 01 00 70 6f ?? 00 00 0a 72 ?? 01 00 70 6f ?? 00 00 0a 14 18 8d}  //weight: 4, accuracy: Low
        $x_4_2 = {13 1a 11 1a 28 ?? 00 00 0a 13 1a 00 72 ?? 06 00 70 28 ?? 00 00 0a 13 1b 11 1b 72 ?? 06 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 13 1b 28 ?? 00 00 0a 11 17 28 ?? 00 00 0a 6f ?? 00 00 0a 72}  //weight: 4, accuracy: Low
        $x_1_3 = "krowemarF\\TEN.tfosorciM\\swodniW\\:C" wide //weight: 1
        $x_1_4 = "91303.0.4v" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            ((2 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Zusy_HNM_2147922895_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNM!MTB"
        threat_id = "2147922895"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 00 43 72 65 61 74 65 54 68 72 65 61 64 00 57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63}  //weight: 10, accuracy: High
        $x_5_2 = {00 64 77 43 72 65 61 74 69 6f 6e 46 6c 61 67 73}  //weight: 5, accuracy: High
        $x_5_3 = {00 62 79 70 61 73 73 00 53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 00}  //weight: 5, accuracy: High
        $x_5_4 = {52 75 6e 74 69 6d 65 43 6f 6d 70 61 74 69 62 69 6c 69 74 79 41 74 74 72 69 62 75 74 65 00 62 79 70 61 73 73 00}  //weight: 5, accuracy: High
        $x_15_5 = {34 44 61 69 6e 00 2e 63 74 6f 72 00 6c 70 41 64 64 72 65 73 73 00 64 77 53 69 7a 65 00 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 00 66 6c 50 72 6f 74 65 63 74 00 6c 70 54 68 72 65 61 64 41 74 74 72 69 62 75 74 65 73 00 64 77 53 74 61 63 6b 53 69 7a 65 00 6c 70 53 74 61 72 74 41 64 64 72 65 73 73}  //weight: 15, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*))) or
            ((1 of ($x_15_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Zusy_HNR_2147922896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNR!MTB"
        threat_id = "2147922896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 00 70 00 68 00 70 00 00 0d 76 00 61 00 6c 00 75 00 65 00 31 00 00 0d 76 00 61 00 6c 00 75 00 65 00 32 00 00 ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_2_2 = {2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_VG_2147922957_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.VG!MTB"
        threat_id = "2147922957"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "91303.0.4v\\" wide //weight: 5
        $x_8_2 = "krowemarF\\TEN.tfosorciM\\swodniW\\:C" wide //weight: 8
        $x_8_3 = "//:ptth" wide //weight: 8
        $x_8_4 = "//:sptth" wide //weight: 8
        $x_1_5 = "FromBase64String" ascii //weight: 1
        $x_1_6 = "DownloadString" ascii //weight: 1
        $x_1_7 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_8_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((2 of ($x_8_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Zusy_AYA_2147922984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AYA!MTB"
        threat_id = "2147922984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "unknownspf_loader" ascii //weight: 2
        $x_1_2 = "$19f13a16-99c6-439d-aa8e-e404e5f2447a" ascii //weight: 1
        $x_1_3 = "activation.php?code=" wide //weight: 1
        $x_1_4 = "deactivation.php?hash=" wide //weight: 1
        $x_1_5 = "Program will be terminated" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNG_2147923008_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNG!MTB"
        threat_id = "2147923008"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 2b 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 41 00 70 00 70 00 31 00 2e 00 52 00 65 00 73 00}  //weight: 10, accuracy: High
        $x_2_2 = "https://i.ibb.co/" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SK_2147923162_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SK!MTB"
        threat_id = "2147923162"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "server1.exe" ascii //weight: 2
        $x_2_2 = "server.Resources.resources" ascii //weight: 2
        $x_2_3 = "$cc7fad03-816e-432c-9b92-001f2d378494" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NM_2147923478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NM!MTB"
        threat_id = "2147923478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 06 11 03 11 02 ?? ?? 00 00 0a 11 04 fe 04 13 0d}  //weight: 2, accuracy: Low
        $x_1_2 = {11 04 11 00 17 59 99 11 04 11 00 99}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNJ_2147923663_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNJ!MTB"
        threat_id = "2147923663"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 [0-149] 3d 00 55 00 54 00 46 00 2d 00 38 00 01 80 ad 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 2f 00 35 00 2e 00 30 [0-229] 0b 3c 00 70 00 72 00 65 00 3e 00 00 0d 3c 00 2f 00 70 00 72 00 65 00 3e 00 00 0d 26 00 71 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_CCJC_2147924339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.CCJC!MTB"
        threat_id = "2147924339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "InfectAD" ascii //weight: 5
        $x_5_2 = "InfectOutlook" ascii //weight: 5
        $x_1_3 = "You can kill a people, but you can't kill an idea. Resistance will continue until the final liberation of all Palestinian lands, and it is only a matter of time." ascii //weight: 1
        $x_1_4 = "KG9iamVjdENsYXNzPWNvbXB1dGVyKQ==" ascii //weight: 1
        $x_1_5 = "TWljcm9zb2Z0RWRnZVVwZGF0ZVRhc2tNYWNoaW5lc1VB" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NP_2147924599_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NP!MTB"
        threat_id = "2147924599"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e0 4a fe 0c 0f 00 fe 0c 0e 00 20 01 00 00 00 59 8f ?? 00 00 01 e0 4a 61 54 fe 0c}  //weight: 2, accuracy: Low
        $x_1_2 = "DownloadData" ascii //weight: 1
        $x_1_3 = "payload" ascii //weight: 1
        $x_1_4 = "RegSetValueEx" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNQ_2147925298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNQ!MTB"
        threat_id = "2147925298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 70 5f 49 6e 65 71 75 61 6c 69 74 79 00 00 00 [0-4] 68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f [0-133] 43 00 3a 00 5c 00 55 00 73 00 65 00 72 00 73 00 5c 00 50 00 75 00 62 00 6c 00 69 00 63 00 5c [0-8] 2e 00 62 00 61 00 74 00 00 0f 43 00 4d 00 44 00 2e 00 65 00 78 00 65}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNQ_2147925298_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNQ!MTB"
        threat_id = "2147925298"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 6e 63 6f 64 69 6e 67 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 47 65 74 53 74 72 69 6e 67 00 67 65 74 5f 4c 65 6e 67 74 68}  //weight: 10, accuracy: High
        $x_1_2 = {61 9a 0d 07 28 ?? ?? ?? ?? 13 ?? 7e ?? ?? ?? ?? 11 ?? 28 ?? ?? ?? ?? 7e ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 ?? 11 ?? 72 ?? ?? ?? ?? 1f}  //weight: 1, accuracy: Low
        $x_1_3 = {49 6e 69 74 69 61 6c 69 7a 65 41 72 72 61 79 00 41 73 73 65 6d 62 6c 79 00 [0-5] 19 ?? 00 [0-37] 00 3d 00 [0-37] 00 3d 00 [0-37] 00 05 00 02 0e 0e 08 08 b7 7a 5c 56 19 34 e0 89 03 06 1d 05}  //weight: 1, accuracy: Low
        $x_1_4 = {54 6f 41 72 72 61 79 00 73 65 74 5f 4b 65 79 00 53 79 73 74 65 6d 2e 53 65 63 75 72 69 74 79 2e 43 72 79 70 74 6f 67 72 61 70 68 79 00 47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 00 42 6c 6f 63 6b 43 6f 70 79 00 52 65 61 64 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 00 57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Zusy_ARA_2147925403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.ARA!MTB"
        threat_id = "2147925403"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\Stealler.pdb" ascii //weight: 2
        $x_2_2 = "://api.telegram.org/bot" wide //weight: 2
        $x_2_3 = "/sendDocument?chat_id=" wide //weight: 2
        $x_2_4 = "Screen({0}).png" wide //weight: 2
        $x_2_5 = "web({0}).png" wide //weight: 2
        $x_2_6 = "key_datas" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AYB_2147925548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AYB!MTB"
        threat_id = "2147925548"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$a7805e28-c8db-482c-8b04-06c0ca884f7d" ascii //weight: 2
        $x_1_2 = "activation.php?code=" wide //weight: 1
        $x_1_3 = "deactivation.php?hash=" wide //weight: 1
        $x_1_4 = "Program will be terminated" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HND_2147925956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HND!MTB"
        threat_id = "2147925956"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 46 45 51 52 42 32 36 58 33 50 44 45 44 46 57 56 42 4e 4e 7a 37 5a 35 4c 71 76 4a 61 59 68 42 71 7a 4d 50 49 51 62 39 33 59 70 6c 67 4e 48 50 4d 34 31 38 39 6c 49 5a 63 56 52 55 4b 49 6b 76 70 44 78 36 58 79 54 79 49 6d 42 65 32 4a 57 71 47 6d 50 4a 59 4f 47 5a 72 75 4b 64 34 63 50 48 77 44 43 6e 67 33 77 [0-255] 54 65 6d 70 6c 61 74 65 [0-48] 41 6c 6c 6f 77 4d 75 6c 74 69 70 6c 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SV_2147926021_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SV!MTB"
        threat_id = "2147926021"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 00 28 14 00 00 0a 72 a9 5c 00 70 28 15 00 00 0a 6f 16 00 00 0a 28 46 00 00 0a 0b 06 28 e5 00 00 0a 0c 20 e8 fb 01 00 8d 81 00 00 01 0d 73 d0 00 00 0a 09 6f e6 00 00 0a 08 8e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNE_2147926440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNE!MTB"
        threat_id = "2147926440"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 6c 6c 49 6d 70 6f 72 74 41 74 74 72 69 62 75 74 65 00 75 52 4c 6d 4f 4e 00 00 00 00}  //weight: 2, accuracy: High
        $x_1_2 = {6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 00 2e 63 74 6f 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNL_2147926441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNL!MTB"
        threat_id = "2147926441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6c 70 4e 75 6d 62 65 72 4f 66 42 79 74 65 73 57 72 69 74 74 65 6e 00 74 68 72 65 61 64 48 61 6e 64 6c 65 00 73 75 73 70 65 6e 64 43 6f 75 6e 74 00 6c 70 53 74 61 72 74 41 64 64 72 00 66 6c 41 6c 6c 6f 63 61 74 69 6f 6e 54 79 70 65 00 66 6c 50 72 6f 74 65 63 74 00 6c 70 41 64 64 72 65 73 73 00 64 77 53 69 7a 65 00 66 6c 4e 65 77 50 72 6f 74 65 63 74 00 6c 70 66 6c 4f 6c 64 50 72 6f 74 65 63 74 00 68 50}  //weight: 2, accuracy: High
        $x_1_2 = {0d 57 00 72 00 69 00 74 00 65 00 20 00 00 11 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 20 00 00 0d 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 0f 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 00 0b 4f 00 70 00 65 00 6e 00 20 00 00 0f 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 00 0d 43 00 6c 00 6f 00 73 00 65 00 20 00 00 0d 48 00 61 00 6e 00 64 00 6c 00 65 00 00 0f 6b 00 65 00 72 00 6e 00 65 00 6c 00 20 00 00 0d 33 00 32 00 2e 00 64 00 6c 00 6c 00 00 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNO_2147926687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNO!MTB"
        threat_id = "2147926687"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3c 4d 6f 64 75 6c 65 3e 00 43 72 65 61 74 65 46 69 6c 65 41 00 [0-160] 00 52 75 6e 50 45 00 [0-160] 00 70 61 79 6c 6f 61 64 00}  //weight: 5, accuracy: Low
        $x_5_2 = {00 47 65 74 50 72 6f 63 65 73 73 42 79 49 64 00}  //weight: 5, accuracy: High
        $x_5_3 = {00 45 78 65 63 75 74 65 00}  //weight: 5, accuracy: High
        $x_5_4 = {00 4b 69 6c 6c 00}  //weight: 5, accuracy: High
        $x_5_5 = {00 4d 61 70 56 69 65 77 4f 66 46 69 6c 65 00}  //weight: 5, accuracy: High
        $x_5_6 = {12 6d 1c 05 20 01 08 12 69 06 20 02 02 18 1d 08}  //weight: 5, accuracy: High
        $x_1_7 = {00 43 6f 70 79 4d 65 6d 6f 72 79 00 [0-255] [0-255] 00 65 6e 74 72 79 00}  //weight: 1, accuracy: Low
        $x_1_8 = {00 65 6e 74 72 79 00 [0-255] [0-255] 00 43 6f 70 79 4d 65 6d 6f 72 79 00}  //weight: 1, accuracy: Low
        $x_1_9 = {00 43 6f 70 79 4d 65 6d 6f 72 79 00 65 6e 74 72 79 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Zusy_HNP_2147926803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNP!MTB"
        threat_id = "2147926803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RmFsc2V8RmFsc2V8" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNS_2147927831_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNS!MTB"
        threat_id = "2147927831"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FEQRB26X3PDEDFWVBNNz7Z5LqvJaYhBqzMPIQb93YplgNHPM4189lIZcVRU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNT_2147927832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNT!MTB"
        threat_id = "2147927832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 64 77 44 65 73 69 72 65 64 41 63 63 65 73 73 00 53 75 63 63 65 73 73 00 68 50 72 6f 63 65 73 73 00 54 68 72 65 61 64 4e 6f 74 49 6e 50 72 6f 63 65 73 73 00 47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 00 49 6e 76 61 6c 69 64 41 64 64 72 65 73 73 00 67 65 74 5f 42 61 73 65 41 64 64 72 65 73 73 00 6c 70 42 61 73 65 41 64 64 72 65 73 73 00 6c 70 41 64 64 72 65 73 73 00 6c 70 53 74 61 72 74 41 64 64 72 65 73 73}  //weight: 2, accuracy: High
        $x_1_2 = {3c 4d 6f 64 75 6c 65 3e 00 47 65 74 48 49 4e 53 54 41 4e 43 45 00 53 79 73 74 65 6d 2e 49 4f 00 67 65 74 5f 49 56 00 73 65 74 5f 49 56 00 76 61 6c 75 65 5f 5f 00 44 6f 77 6e 6c 6f 61 64 44 61 74 61 00 4e 6f 74 4d 61 70 70 65 64 44 61 74 61 00 4e 6f 54 78 66 4d 65 74 61 64 61 74 61 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EM_2147928061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EM!MTB"
        threat_id = "2147928061"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_7_1 = {16 13 09 2b 30 11 06 11 09 94 11 06 11 09 17 58 94 31 1c 11 06 11 09 94 13 0a 11 06 11 09 11 06 11 09 17 58 94 9e 11 06 11 09 17 58 11 0a 9e 11 09 17 58 13 09 11 09 11 06 8e 69 17 59 11 08 59 32 c3}  //weight: 7, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GB_2147928067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GB!MTB"
        threat_id = "2147928067"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07}  //weight: 1, accuracy: High
        $x_1_2 = {7e 01 00 00 04 8e 69 8d 1a 00 00 01 0a 16 13 07}  //weight: 1, accuracy: High
        $x_1_3 = {28 09 00 00 06 75 10 00 00 01 28 07 00 00 06 0a}  //weight: 1, accuracy: High
        $x_1_4 = "costura.costura.dll.compressed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNAB_2147928338_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNAB!MTB"
        threat_id = "2147928338"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 68 61 72 65 4d 6f 64 65 00 53 69 7a 65 4f 66 49 6d 61 67 65 00 45 6e 64 49 6e 76 6f 6b 65 00 42 65 67 69 6e 49 6e 76 6f 6b 65 00}  //weight: 2, accuracy: High
        $x_1_2 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 42 61 73 65 4f 66 44 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 66 69 6c 65 4e 61 6d 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 50 72 6f 63 65 73 73 4d 6f 64 75 6c 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 6e 75 6d 62 65 72 4f 66 42 79 74 65 73 54 6f 4d 61 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 6e 65 77 50 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 6f 6c 64 50 72 6f 74 65 63 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 66 69 6c 65 4f 66 66 73 65 74 4c 6f 77 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 64 65 73 69 72 65 64 41 63 63 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 66 6c 61 67 73 41 6e 64 41 74 74 72 69 62 75 74 65 73 00}  //weight: 1, accuracy: High
        $x_1_12 = {2e 00 74 00 6d 00 70 00 00 00 00 00 28 00 02 00 01 00 4c 00 65 00 67 00 61 00 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SF_2147928835_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SF!MTB"
        threat_id = "2147928835"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 03 04 05 0e 04 6f 15 00 00 06 2c 02 17 2a 07 17 d6 0b 07 1b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GC_2147928959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GC!MTB"
        threat_id = "2147928959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07}  //weight: 1, accuracy: High
        $x_1_2 = {7e 01 00 00 04 8e 69 8d 1b 00 00 01 0a 16 13 07}  //weight: 1, accuracy: High
        $x_1_3 = "costura.costura.dll.compressed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNAK_2147929729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNAK!MTB"
        threat_id = "2147929729"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 64 6d 61 44 79 6e 61 6d 69 63 43 6f 6e 64 00 4d 69 63 72 6f 73 6f 66 74 2e 56 69 73 75 61 6c 42 61 73 69 63 2e 41 70 70 6c 69 63 61 74 69 6f 6e}  //weight: 2, accuracy: High
        $x_1_2 = {00 47 65 74 49 6e 73 74 61 6e 63 65 00 52 75 6e 43 6f 6e 64 69 74 69 6f 6e 00 53 79 73 74 65 6d 2e}  //weight: 1, accuracy: High
        $x_1_3 = {2e 64 6c 6c 00 00 00 09 ?? 00 ?? 00 ?? 00 ?? 00 00 03 25 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 00 08 b7 7a 5c 56 19 34 e0 89 08 b0 3f 5f 7f 11 d5 0a 3a 03 20 00 01 03 00 00 01 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SWA_2147931289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SWA!MTB"
        threat_id = "2147931289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 05 03 16 03 8e 69 6f 14 00 00 0a 00 11 05 6f 15 00 00 0a 00 00 de 14 11 05 14 fe 01 13 07 11 07 2d 08 11 05 6f 16 00 00 0a 00 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HNAR_2147931550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HNAR!MTB"
        threat_id = "2147931550"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 00 6d 00 61 00 69 00 6c 00 00 11 47 00 65 00 74 00 42 00 79 00 74 00 65 00 73 00 00 17 53 00 4d 00 54 00 50 00 20 00 53 00 65 00 72 00 76 00 65 00 72 00 00 0f 4e 00 6f 00 74 00 68 00 69 00 6e 00 67 00 00 03 00 00 00 0f 4f 00 75 00 74 00 6c 00 6f 00 6f 00 6b}  //weight: 2, accuracy: High
        $x_2_2 = {15 77 00 6f 00 77 00 5f 00 6c 00 6f 00 67 00 69 00 6e 00 73}  //weight: 2, accuracy: High
        $x_2_3 = {15 6f 00 72 00 69 00 67 00 69 00 6e 00 5f 00 75 00 72 00 6c 00}  //weight: 2, accuracy: High
        $x_1_4 = {5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 4c 00 6f 00 67 00 69 00 6e 00 20 00 44 00 61 00 74 00 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GD_2147931603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GD!MTB"
        threat_id = "2147931603"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07}  //weight: 2, accuracy: High
        $x_1_2 = {7e 01 00 00 04 8e 69 8d 16 00 00 01 0a 16 13 07}  //weight: 1, accuracy: High
        $x_1_3 = "Fsignature.compressed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SL_2147931780_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SL!MTB"
        threat_id = "2147931780"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 0a 8f 19 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd}  //weight: 2, accuracy: High
        $x_2_2 = "server.Resources.resources" ascii //weight: 2
        $x_2_3 = "Gatphor Pineice All Right Reserved" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NITA_2147932225_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NITA!MTB"
        threat_id = "2147932225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {14 73 15 02 00 0a 0c 08 1f 20 6f ?? 02 00 0a 0d 73 17 02 00 0a 13 04 11 04 17 6f ?? 02 00 0a 11 04 09 06 6f ?? 02 00 0a 13 05 73 1a 02 00 0a 13 06 11 06 11 05 17 73 1b 02 00 0a 13 07 11 07 07 16 07 8e 69 6f ?? 02 00 0a 11 07 6f ?? 02 00 0a 11 06 6f ?? 02 00 0a 13 08 11 06 6f ?? 02 00 0a 11 07 6f ?? 02 00 0a 11 08 28 ?? 02 00 0a 2a}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NITA_2147932225_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NITA!MTB"
        threat_id = "2147932225"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 1b 11 1b 14 6f 02 00 00 2b 26 06 6f 74 00 00 06 2d 10 11 1c 7b 5b 00 00 04 1f 64 6f 1a 01 00 0a 2c e8 11 05 6f 1b 01 00 0a 11 05 6f 1c 01 00 0a 6f 1d 01 00 0a 1b 33 1d 11 1c 7b 5a 00 00 04 11 05 6f 1c 01 00 0a 6f 1e 01 00 0a 6f e6 00 00 0a 6f e7 00 00 0a de 0c}  //weight: 2, accuracy: High
        $x_1_2 = {17 28 d0 00 00 0a 0b 12 01 28 d1 00 00 0a 1f 0d 33 07 28 d2 00 00 0a 2b 4f 12 01 28 d1 00 00 0a 1e 33 23 06 6f d3 00 00 0a 16 31 d4 06 06 6f d3 00 00 0a 17 59 6f d4 00 00 0a 72 49 02 00 70 28 d5 00 00 0a 2b ba 12 01 28 d6 00 00 0a 2c b1 06 12 01 28 d6 00 00 0a 6f ce 00 00 0a 72 51 02 00 70 28 d5 00 00 0a 2b 98}  //weight: 1, accuracy: High
        $x_1_3 = "Start-Process PowerShell" ascii //weight: 1
        $x_1_4 = "ExecutionPolicy Bypass" ascii //weight: 1
        $x_1_5 = "USERNAME_TARGET_CREDENTIALS" ascii //weight: 1
        $x_1_6 = "set_VirtualKeyCode" ascii //weight: 1
        $x_1_7 = "set_ControlKeyState" ascii //weight: 1
        $x_1_8 = "PromptForPassword" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EAZZ_2147932235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EAZZ!MTB"
        threat_id = "2147932235"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 23 00 00 00 00 00 00 3a 40 07 6f d7 00 00 0a 5a 23 00 00 00 00 00 40 50 40 58 28 d8 00 00 0a 28 d9 00 00 0a 28 da 00 00 0a 0d 12 03 28 db 00 00 0a 28 46 00 00 0a 0a 08 17 58 0c 08 1b 3f bd ff ff ff}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AMCZ_2147932345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AMCZ!MTB"
        threat_id = "2147932345"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 00 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0d 09 04 16 05 8e 69 6f ?? 00 00 0a 13 04 de 16}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AYC_2147932497_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AYC!MTB"
        threat_id = "2147932497"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ExclusionLoader.pdb" ascii //weight: 2
        $x_2_2 = "$2f9ce5c0-3881-418e-b840-635004632362" ascii //weight: 2
        $x_1_3 = "WinDefExclusion" ascii //weight: 1
        $x_1_4 = "command = 'Add-MpPreference -ExclusionPath" wide //weight: 1
        $x_1_5 = "FolderNameRandomName" ascii //weight: 1
        $x_1_6 = "Command \"Start-Process" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GE_2147932968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GE!MTB"
        threat_id = "2147932968"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07}  //weight: 2, accuracy: High
        $x_2_2 = {7e 01 00 00 04 8e 69 8d ?? 00 00 01 0a 16 13 07}  //weight: 2, accuracy: Low
        $x_1_3 = "Fsignature.compressed" ascii //weight: 1
        $x_1_4 = "pfx.strongname.compressed" ascii //weight: 1
        $x_1_5 = "pfx.stgname.compressed" ascii //weight: 1
        $x_1_6 = "crt.pfx.compressed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Zusy_EAQH_2147934427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EAQH!MTB"
        threat_id = "2147934427"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {20 00 40 01 00 8d 84 00 00 01 0a 38 09 00 00 00 03 06 16 07 6f 26 01 00 0a 02 06 16 06 8e 69 6f 27 01 00 0a 25 0b 3a e5 ff ff ff 2a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EACZ_2147934429_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EACZ!MTB"
        threat_id = "2147934429"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {17 6f 2a 00 00 0a 13 07 28 2f 00 00 0a 11 07 16 9a 28 30 00 00 0a 6f 31 00 00 0a 13 08 11 08 72 3f 00 00 70 6f 32 00 00 0a 2c 03 11 08 0c 11 07 17 9a 28 30 00 00 0a 13 09 07 11 08 28 20 00 00 0a 11 09 28 33 00 00 0a de 03}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_MBS_2147934927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.MBS!MTB"
        threat_id = "2147934927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 10 00 72 fc f8 01 70 11 10}  //weight: 1, accuracy: High
        $x_1_2 = {13 12 11 12 14 fe 03}  //weight: 1, accuracy: High
        $x_2_3 = "XSPCnxO3J5eKgrbQ3R.7ljbNpdbPT7" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AYD_2147935287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AYD!MTB"
        threat_id = "2147935287"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 06 09 91 09 1f 2a 5a 20 00 01 00 00 5d d2 61 d2 9c 08 09 8f 16 00 00 01 25 47 07 09 07 8e 69 5d 91 61 d2 52 09 17 58 0d 09 06 8e 69 32 d0}  //weight: 2, accuracy: High
        $x_1_2 = "$f011c587-a767-47b5-b022-8be44153fc4f" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SWB_2147935621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SWB!MTB"
        threat_id = "2147935621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 08 07 6f ?? 00 00 0a 08 6f ?? 00 00 0a 02 16 02 8e 69 6f ?? 00 00 0a 0d de 0a 08 2c 06 08 6f ?? 00 00 0a dc}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EADJ_2147935737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EADJ!MTB"
        threat_id = "2147935737"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {13 10 11 10 20 af 3d d6 9d 20 e3 65 17 3d 59 65 20 05 ab 58 e8 20 59 70 dd 5c 59 20 2d 97 86 7a 65 59 59 65 61 20 07 92 65 73 5a 25 13 0f 1f 4d}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_A_2147935981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.A!MTB"
        threat_id = "2147935981"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8d 64 00 00 01 25 16 02 20 00 00 ff 00 5f 1f 10 63 d2 9c 25 17 02 20 00 ff 00 00 5f 1e 63}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SPS_2147936203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SPS!MTB"
        threat_id = "2147936203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BobuxManRemastered.exe" ascii //weight: 1
        $x_1_2 = "right clicking the red box won't save you" ascii //weight: 1
        $x_1_3 = "RESET PURRSONAL COED" ascii //weight: 1
        $x_1_4 = "Your money:" ascii //weight: 1
        $x_1_5 = "U HAV BEAN HAKED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_B_2147936263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.B!MTB"
        threat_id = "2147936263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 75 08 00 00 1b 11 07 8f 91 00 00 01 25 71 91 00 00 01 11 07 04 58 0e 06 59 20 ff 00 00 00 5f d2 61 d2 81 91 00 00 01}  //weight: 2, accuracy: High
        $x_1_2 = "8242761c-2498-46e6-9a85-f3f6a9b9e3f2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AD_2147936271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AD!MTB"
        threat_id = "2147936271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8d 08 00 00 01 25 16 d0 0c 00 00 01 28 28 00 00 0a a2 28 2a 00 00 0a 28 29 00 00 0a 74 08 00 00 1b 73 2b 00 00 0a 72 cd 01 00 70 6f 2c 00 00 0a 6f 2d 00 00 0a 6f 2e 00 00 0a 6f 2f 00 00 0a 6f 30 00 00 0a}  //weight: 2, accuracy: High
        $x_1_2 = "c3aa2b70-2591-44c3-8320-68d8c65bfd4c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PKM_2147936654_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PKM!MTB"
        threat_id = "2147936654"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {09 11 04 91 13 05 00 07 06 11 05 6e 21 34 0f cf 47 17 00 00 00 59 d2 6f ?? 00 00 0a 00 00 11 04 17 58 13 04 11 04 09 8e 69}  //weight: 3, accuracy: Low
        $x_2_2 = "usaaaa" wide //weight: 2
        $x_1_3 = "$b9bced44-893c-4def-a0d9-350d4631acf5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_CCJR_2147936886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.CCJR!MTB"
        threat_id = "2147936886"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {09 11 05 02 11 05 91 08 61 07 06 91 61 b4 9c 38 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SCA_2147936961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SCA!MTB"
        threat_id = "2147936961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 2b 24 07 06 07 06 93 02 7b ?? ?? ?? 04 04 20 2a e7 e5 12 20 7f e7 a6 fa 59 20 a4 ff 3e 18 61 5f 91 04 60 61 d1 9d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GPPC_2147938487_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GPPC!MTB"
        threat_id = "2147938487"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8d 07 00 00 01 25 16 03 1f 4d 6f ?? 00 00 0a d2 9c 25 17 03 1f 5a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PGZU_2147938921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PGZU!MTB"
        threat_id = "2147938921"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 0a 8f ?? 00 00 01 25 47 08 d2 61 d2 52 11 0a 20 ff 00 00 00 5f 2d 0b 08 08 5a 20 b7 5c 8a 00 6a 5e 0c 11 0a 17 58 13 0a 11 0a 11 05 8e 69 32 cd}  //weight: 1, accuracy: Low
        $x_4_2 = {73 00 65 00 72 00 76 00 65 00 72 00 31 00 2e 00 65 00 78 00 65}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_PGZ_2147939659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.PGZ!MTB"
        threat_id = "2147939659"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UmVtb3ZlLUl0ZW1Qcm9wZXJ0eSAtUGF0aCAiSEtDVTpcUkNXTVxyYyIgLU5hbWUgKg0" ascii //weight: 1
        $x_4_2 = "KTmV3LUl0ZW1Qcm9wZXJ0eSAtUGF0aCAiSEtDVTpcUkNXTVxyYyIgLU5hbWUgIiRhcmdzIg" ascii //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_EFH_2147941312_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.EFH!MTB"
        threat_id = "2147941312"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {45 07 00 00 00 02 00 00 00 0b 00 00 00 14 00 00 00 1b 00 00 00 21 00 00 00 2c 00 00 00 3e 00 00 00 2b 4f 73 03 00 00 0a 0b 17 2b d4 7e 01 00 00 0a 0c 18 2b cb 02 17 da 0d 19 2b c4 16 13 04 1a 2b be}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SWE_2147941423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SWE!MTB"
        threat_id = "2147941423"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 01 00 00 70 28 1e 00 00 0a 0b 07 28 03 00 00 2b 16 33 21 72 0f 00 00 70 28 20 00 00 0a 72 29 00 00 70 28 21 00 00 0a 28 22 00 00 0a 26 1f 64}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GPAN_2147941960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GPAN!MTB"
        threat_id = "2147941960"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 07 8e 69 5d 91 61 d2 81 ?? 00 00 01 11 08 17 58 13 08 11 08 11 06 8e 69}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_HBA_2147942849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.HBA!MTB"
        threat_id = "2147942849"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {3c 4d 6f 64 75 6c 65 3e 00 ?? ?? ?? ?? ?? ?? ?? ?? 2e 64 6c 6c [0-255] 00 00 00 [0-64] 00 55 52 6c 4d 4f 4e 2e 64 4c 6c 00}  //weight: 5, accuracy: Low
        $x_1_2 = {46 00 69 00 6c 00 65 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 00 00 00 00 30 00 2e 00 30 00 2e 00 30 00 2e 00 30 00 00 00 3c 00 0d 00 01 00 49 00 6e 00 74 00 65 00 72 00 6e 00 61 00 6c 00 4e 00 61 00 6d 00 65 00 00 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 00 64 00 6c 00 6c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_NU_2147944036_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.NU!MTB"
        threat_id = "2147944036"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 25 17 6f ?? 00 00 0a 25 17 6f ?? 00 00 0a 25 72 ?? 00 00 70 6f ?? 00 00 0a 25 72 ?? 00 00 70 06 72 ?? 00 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 26}  //weight: 3, accuracy: Low
        $x_1_2 = "$6ef9b1e5-30d4-4112-ba97-eebc5f8ac5d8" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_BAC_2147944121_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.BAC!MTB"
        threat_id = "2147944121"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 fe 0c 01 00 fe 0c 03 00 20 00 01 00 00 fe 0c 00 00 fe 0c 00 00 8e 69 20 01 00 00 00 59 fe 0c 03 00 59 91 58 fe 0c 02 00 59 20 00 01 00 00 5d d2 9c 00 fe 0c 03 00 20 01 00 00 00 58 fe 0e 03 00 fe 0c 03 00 fe 0c 00 00 8e 69 fe 04 fe 0e 04 00 fe 0c 04 00 3a a6 ff ff ff}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SLIO_2147944453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SLIO!MTB"
        threat_id = "2147944453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 9a 0c 08 16 17 6f 66 00 00 0a 12 03 28 67 00 00 0a 2c 20 72 ab 01 00 70 09 8c 3d 00 00 01 28 68 00 00 0a 28 12 00 00 0a 08 28 19 00 00 06 28 14 00 00 06 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SLF_2147944919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SLF!MTB"
        threat_id = "2147944919"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 7c 00 00 0a 13 05 11 04 28 7d 00 00 0a 13 06 16 13 07 2b 34 11 06 11 07 9a 25 28 45 00 00 0a 28 46 00 00 0a 13 08 28 7e 00 00 0a 11 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_AI_2147945014_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.AI!MTB"
        threat_id = "2147945014"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 3e 00 00 04 20 36 fc 3a 26 20 3a b3 91 9f 61 20 03 00 00 00 63 20 e1 69 35 f7 61 7d 4d 00 00 04 20 3e 00 00 00 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_GAF_2147945554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.GAF!MTB"
        threat_id = "2147945554"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "MTg4LjIxNC4xMDcuMjA=" ascii //weight: 2
        $x_1_2 = "R2xvYmFsXFxXaW5FeHBsb3JlclN5bmM=" ascii //weight: 1
        $x_1_3 = "U29mdHdhcmVcXE1pY3Jvc29mdFxcV2luZG93c1xcQ3VycmVudFZlcnNpb25cXFJ1bg==" ascii //weight: 1
        $x_1_4 = "RXhwbG9yZXJTZXJ2aWNl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zusy_SM_2147947056_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zusy.SM"
        threat_id = "2147947056"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zusy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 07 02 07 91 07 03 28 7b 00 00 06 9c 07 17 d6 0b 07 06 31 eb}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

