rule Trojan_MSIL_Cerbu_NB_2147840352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.NB!MTB"
        threat_id = "2147840352"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 28 5e 00 00 0a 0a 28 ?? 00 00 0a 06 16 06 8e 69 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "ScanProcesses" ascii //weight: 1
        $x_1_3 = "remove_PROCAt" ascii //weight: 1
        $x_1_4 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_ACE_2147840880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.ACE!MTB"
        threat_id = "2147840880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 09 06 4a 09 8e 69 5d 91 08 06 4a 91 61 d2 6f ?? ?? ?? 0a 06 1a 58 06 4a 54 06 06 1a 58 4a 17}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_GEN_2147841022_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.GEN!MTB"
        threat_id = "2147841022"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 07 1f 10 32 d4 06 16 06 16 95 07 16 95 61 20 a9 f2 0a d2 58 9e 06 17 06 17 95 07 17 95 5a 20 a5 55 19 59 5a 9e 06 18 06 18 95 07 18 95}  //weight: 10, accuracy: High
        $x_1_2 = "NeoSignTools.exe" ascii //weight: 1
        $x_1_3 = "ToBase64String" ascii //weight: 1
        $x_1_4 = "ConfusedByAttribute" ascii //weight: 1
        $x_1_5 = "DecodeWithMatchByte" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_ACU_2147845653_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.ACU!MTB"
        threat_id = "2147845653"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 0a 2b 39 02 28 17 00 00 0a 72 01 00 00 70 06 17 58 0b 12 01 28 18 00 00 0a 28 19 00 00 0a 6f 1a 00 00 0a 28 10 00 00 06 72 0d 00 00 70 28 19 00 00 0a 6f 16 00 00 0a 00 06 17 58 0a 06 1c fe 04 0c 08 2d bf}  //weight: 2, accuracy: High
        $x_1_2 = "Health Monitoring App is a comprehensive tool for tracking and improving your overall wellness" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_AMAA_2147892238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.AMAA!MTB"
        threat_id = "2147892238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 06 11 07 11 05 11 07 28 ?? ?? 00 06 20 ?? ?? 00 00 61 d1 9d 20 ?? 00 00 00 28 ?? ?? 00 06 13 0c 2b a7}  //weight: 5, accuracy: Low
        $x_5_2 = {06 07 06 07 93 1f 66 61 02 61 d1 9d 2b 12 07 17 59 25 0b 16 2f ea}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_AMAA_2147892238_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.AMAA!MTB"
        threat_id = "2147892238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 8e 69 0b 7e ?? 00 00 0a 20 ?? ?? 00 00 20 ?? ?? 00 00 1f 40 28 ?? 00 00 06 0c 16 08 07 28 ?? 00 00 0a 7e ?? 00 00 0a 16 08 7e ?? 00 00 0a 16 7e ?? 00 00 0a 28 ?? 00 00 06 15 28 ?? 00 00 06 26 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0a 20 d0 07 00 00 28 04 00 00 06}  //weight: 1, accuracy: High
        $x_1_3 = "VirtualAlloc" ascii //weight: 1
        $x_1_4 = "WaitForSingleObject" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_CM_2147892297_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.CM!MTB"
        threat_id = "2147892297"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 09 28 2d 00 00 06 09 73 ?? ?? 00 0a 28 ?? ?? 00 0a 13 06 11 06 02 7b ?? ?? 00 04 07 6f ?? ?? 00 0a 7b ?? ?? 00 04 6a 2e 3c 72 ?? ?? 00 70 02 7b ?? ?? 00 04 07 6f ?? ?? 00 0a 7c ?? ?? 00 04 28 ?? ?? 00 0a 72 ?? ?? 00 70 12 06 28 ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 06 09 28 ?? ?? 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "TrainControlUpdater" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_GP_2147894384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.GP!MTB"
        threat_id = "2147894384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {00 7e 13 00 00 0a 1a 2c 1f 16 25 2d 0c 2b 3f 16 20 7f 96 98 00 2b 3e 2b 43 12 02 2b 42 2b 47 1e 2d 4b 26 18 2b 4a 2b 4b 2b 4c 07 28 01 00 00 06 26}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_AMBA_2147895792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.AMBA!MTB"
        threat_id = "2147895792"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 02 91 20 ?? ff ff ff 5f 1f 18 62 0a 20 ?? 00 00 00 16 39}  //weight: 1, accuracy: Low
        $x_1_2 = {04 02 17 58 91 1f 10 62 60 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_AC_2147896123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.AC!MTB"
        threat_id = "2147896123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0a 06 17 6f 5f 00 00 0a 06 03 6f 60 00 00 0a 06 04 6f 61 00 00 0a 73 62 00 00 0a 0b 06 6f 67 00 00 0a 0c 07 08 17 73 64 00 00 0a 0d 02 28 1e 00 00 06 13 04 09 11 04 16 11 04 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_AMBC_2147902845_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.AMBC!MTB"
        threat_id = "2147902845"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 11 04 08 11 04 08 8e 69 5d 91 9c 00 11 04 17 58 13 04}  //weight: 2, accuracy: High
        $x_2_2 = {08 09 06 09 91 07 09 91 28 ?? 00 00 06 9c 00 09 17 58 0d 09 06 8e 69}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_KAAM_2147905847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.KAAM!MTB"
        threat_id = "2147905847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 06 07 02 07 91 17 61 d2 9c 00 07 17 58 0b 07 02 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_AMA_2147921783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.AMA!MTB"
        threat_id = "2147921783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 5b 26 11 [0-20] 03 12 ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 8f ?? 00 00 01 25 71 ?? 00 00 01 06 12 ?? 28 ?? 00 00 0a 28 ?? 00 00 0a 91 61 d2 81 ?? 00 00 01 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_SOC_2147923706_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.SOC!MTB"
        threat_id = "2147923706"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 21 00 00 0a 25 72 01 00 00 70 6f 22 00 00 0a 25 72 17 00 00 70 6f ?? ?? ?? 0a 25 16 6f 24 00 00 0a 25 17 6f ?? ?? ?? 0a 28 26 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_NC_2147924597_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.NC!MTB"
        threat_id = "2147924597"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "69F24208-BABA-4074-B545-74B2F45DD79D" ascii //weight: 3
        $x_1_2 = {0d 07 8e 69 13 04 08 8e 69 13 05 16}  //weight: 1, accuracy: High
        $x_1_3 = {11 08 11 0c 07 11 06 11 0c 58 91 9c 11 0c 17 58}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_AMCQ_2147927772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.AMCQ!MTB"
        threat_id = "2147927772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 17 6f ?? 00 00 0a 06 18 6f ?? 00 00 0a 73 ?? 00 00 0a 25 06 03 04 6f ?? 00 00 0a 17 73 ?? 00 00 0a 25 02 16 02 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b de 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_ARA_2147939926_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.ARA!MTB"
        threat_id = "2147939926"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 00 04 00 00 6a 5a 20 00 04 00 00 6a 5a 20 00 04 00 00 6a 5a 0b 06 6f ?? ?? ?? 0a 2c 0b 06 6f ?? ?? ?? 0a 07 fe 02 2b 01 16 0c de 05}  //weight: 2, accuracy: Low
        $x_2_2 = "\\uihdfhjdsahfdsf.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_AKQ_2147948430_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.AKQ!MTB"
        threat_id = "2147948430"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {08 02 28 2e 00 00 0a 7e 08 00 00 04 15 16 28 2f 00 00 0a 16 9a 28 a7 01 00 06 28 37 00 00 0a de 0f 25 28 33 00 00 0a 13 04 28 34 00 00 0a de 00 02 28 2e 00 00 0a 7e 08 00 00 04 15 16 28 2f 00 00 0a 19 9a 28 35 00 00 0a 2c 18 08 1c 28 38 00 00 0a de 0f 25 28 33 00 00 0a 13 05 28 34 00 00 0a de 00 08 28 39 00 00 0a 26 de 0f}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_SLGB_2147952771_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.SLGB!MTB"
        threat_id = "2147952771"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 fc 00 00 0a 6f 90 00 00 0a 06 07 6f dd 00 00 0a 17 73 93 00 00 0a 0c 08 02 16 02 8e 69 6f 95 00 00 0a 08 6f 97 00 00 0a 06 28 8e 02 00 06 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Cerbu_ZTN_2147953207_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Cerbu.ZTN!MTB"
        threat_id = "2147953207"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cerbu"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {11 04 8e 69 8d ?? 00 00 01 13 05 16 13 06 2b 19 00 11 05 11 06 11 04 11 06 91 20 aa 00 00 00 61 d2 9c 00 11 06 17 58 13 06 11 06 11 04 8e 69 fe 04 13 07 11 07 2d d9}  //weight: 6, accuracy: Low
        $x_4_2 = {06 07 02 07 91 03 07 03 8e 69 5d 91 61 07 20 00 01 00 00 5d 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 2d d9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

