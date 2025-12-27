rule Trojan_MSIL_NjRAT_DC_2147783879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.DC!MTB"
        threat_id = "2147783879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a a2 25 1f 62 11 62 2d 03 14 2b 07 11 62 6f ?? ?? ?? 0a a2 25 1f 63 11 63 2d 03 14 2b 07 11 63 6f ?? ?? ?? 0a a2 25 1f 64 11 64 2d 03 14 2b 07 11 64 6f ?? ?? ?? 0a a2 28 ?? ?? ?? 0a 13 65 11 65 28 ?? ?? ?? 0a 13 66 11 66}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "ToString" ascii //weight: 1
        $x_1_4 = "WindowsFormsApp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_C_2147841903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.C!MTB"
        threat_id = "2147841903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 0a 0d 09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 08 17 58}  //weight: 2, accuracy: High
        $x_2_2 = {00 00 01 11 05 11 0a 74 ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b 74 ?? 00 00 1b 11 09 11 0c 58 1f ?? 58 11 08 5d 93 61 d1 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_D_2147843113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.D!MTB"
        threat_id = "2147843113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 04 25 2d 17 26 7e ?? 00 00 04 fe 06 07 00 00 06 73 ?? 00 00 0a 25 80 ?? 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 73}  //weight: 2, accuracy: Low
        $x_2_2 = "/AppData/Local/Temp/" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSJX_2147844436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSJX!MTB"
        threat_id = "2147844436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 07 08 6f 0c 00 00 0a 17 73 ?? ?? ?? 0a 13 04 00 11 04 02 16 02 8e 69 6f ?? ?? ?? 0a 00 11 04 6f ?? ?? ?? 0a 00 00 de 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSJY_2147844437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSJY!MTB"
        threat_id = "2147844437"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0d 1f 1a 28 ?? ?? ?? 0a 72 bd 01 00 70 20 ?? ?? ?? 00 28 ?? ?? ?? 06 08 28 ?? ?? ?? 0a 13 04 73 ?? ?? ?? 0a 28 ?? ?? ?? 0a 09 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 05 2b 03 0c 2b a5 11 04 11 05 28 ?? ?? ?? 0a 2b 06 0b 38 78 ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSJW_2147844537_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSJW!MTB"
        threat_id = "2147844537"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 19 17 20 65 01 00 00 20 40 01 00 00 28 10 00 00 06 0b 19 13 07 11 07 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 07 20 ed 64 30 0d 18 28 0e 00 00 06 28 02 00 00 06 0c 08 20 d8 02 00 00 20 e7 02 00 00 28 11 00 00 06 14 16 8d 01 00 00 01 20 ab 00 00 00 20 ec 00 00 00 28 22 00 00 06 26 de 3b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSMN_2147846445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSMN!MTB"
        threat_id = "2147846445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 0a 00 00 0a 28 01 00 00 2b 0a 72 2f 01 00 70 0b 16 0c 2b 2d 06 08 6f 30 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_B_2147846852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.B!MTB"
        threat_id = "2147846852"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 14 72 ?? ?? ?? 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 14 72 ?? ?? ?? 70 18 8d ?? 00 00 01 13 ?? 11 ?? 16 14 a2 00 11 ?? 17 14 a2 00 11 ?? 14 14 14 28}  //weight: 2, accuracy: Low
        $x_1_2 = "get_CurrentDomain" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSMT_2147847619_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSMT!MTB"
        threat_id = "2147847619"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {26 72 af 00 00 70 28 ?? ?? ?? 0a 00 28 06 00 00 06 6f ?? ?? ?? 0a 72 d3 00 00 70 72 af 00 00 70 6f ?? ?? ?? 0a 00 73 ?? ?? ?? 0a 0d 09 6f ?? ?? ?? 0a 72 af 00 00 70 6f ?? ?? ?? 0a 00 09 6f 4c 00 00 0a 26 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_H_2147849351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.H!MTB"
        threat_id = "2147849351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {57 95 a2 3d 09 1f 00 00 00 00 00 00 00 00 00 00 02 00 00 00 bb 00 00 00 19 00 00 00 f8 01 00 00 7b 08}  //weight: 2, accuracy: High
        $x_2_2 = "WindowsApplication35.Resources.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSQQ_2147849652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSQQ!MTB"
        threat_id = "2147849652"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 3f 00 00 0a 74 09 00 00 01 80 0b 00 00 04 1b 39 d4 ff ff ff 11 05 74 38 00 00 01 28 40 00 00 0a 74 34 00 00 01 0a dd 68 00 00 00 73 41 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_NJR_2147851268_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.NJR!MTB"
        threat_id = "2147851268"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {5a 13 0e 11 0e 11 08 61 11 04 06 61 20 ?? ?? ?? 0c 6e 5a 58 13 0e 17 13 0f 38 ?? ?? ?? ff d0 ?? ?? ?? 02 20 ?? ?? ?? 22 20 ?? ?? ?? 2e 58 13 0f 26}  //weight: 5, accuracy: Low
        $x_1_2 = "ygTfMOZ" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAA_2147852100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAA!MTB"
        threat_id = "2147852100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 07 91 07 07 11 08 95 07 11 04 95 58 6e 20 ?? 00 00 00 6a 5f 69 95 61 d2 9c 11 07}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSUF_2147852495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSUF!MTB"
        threat_id = "2147852495"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 20 e8 03 00 00 28 ?? 00 00 0a 00 72 63 00 00 70 0c 08 7e 02 00 00 04 28 ?? 00 00 06 0d 09 2c 0d 00 7e 02 00 00 04 28 ?? 00 00 0a 26}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSVX_2147888833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSVX!MTB"
        threat_id = "2147888833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 08 16 6f ?? 00 00 0a 13 05 12 05 28 ?? 00 00 0a 6f ?? 00 00 0a 16 28 ?? 00 00 06 39 c5 ff ff ff 26 20 04 00 00 00 fe 0e 0a 00 28 ?? 00 00 06 39 8b ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSWB_2147889062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSWB!MTB"
        threat_id = "2147889062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 0c 17 28 ?? 00 00 06 3a 52 00 00 00 26 20 02 00 00 00 38 2d 00 00 00 08 14 72 e3 00 00 70 16 8d 14 00 00 01 14 14 14}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSWD_2147889063_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSWD!MTB"
        threat_id = "2147889063"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0b 20 06 00 00 00 38 32 00 00 00 38 8a 00 00 00 7e 0c 00 00 04 07 09 16 6f ?? 00 00 0a 13 04 12 04 28 ?? 00 00 0a 6f ?? 00 00 0a 38 32 00 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PSWG_2147889173_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PSWG!MTB"
        threat_id = "2147889173"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 0a 31 50 73 08 00 00 0a 13 20 07 16 9a 7e 19 00 00 04 07 17 9a 7e 19 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 13 1f 11 20 02 11 1f 02 8e b7 11 1f da 6f ?? 00 00 0a 11 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_NA_2147891169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.NA!MTB"
        threat_id = "2147891169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 9a 18 9a 6f ?? 00 00 0a 74 ?? 00 00 1b 28 ?? 00 00 06 28 ?? 00 00 0a 06 07 9a 19 9a 0d 28 ?? 00 00 0a 09 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 7e ?? 00 00 04 0d 28 ?? 00 00 0a 09 28 ?? 00 00 0a 28 ?? 00 00 06 6f ?? 00 00 0a 28 ?? 00 00 0a 2c 07}  //weight: 5, accuracy: Low
        $x_1_2 = "jdjzpnnrsljwqtvx.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_NR_2147892772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.NR!MTB"
        threat_id = "2147892772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {26 08 09 02 09 91 11 04 11 04 06 84 95 11 04 07 84 95 d7 6e ?? ?? ?? ?? ?? 6a 5f b7 95 61 86 9c}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_NR_2147892772_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.NR!MTB"
        threat_id = "2147892772"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 72 10 4a 01 70 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 0c 08 6f ?? ?? ?? 0a 14 14 6f ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "svchost.My.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PTAI_2147894665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PTAI!MTB"
        threat_id = "2147894665"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {d0 25 00 00 06 26 07 28 ?? 02 00 06 28 ?? 02 00 06 8e b7 16 fe 02 0d 09 39 4b ff ff ff 17 8d 4e 00 00 01 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PTAY_2147895522_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PTAY!MTB"
        threat_id = "2147895522"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {73 30 00 00 0a 28 ?? 00 00 0a 72 1b 01 00 70 28 ?? 00 00 0a 6f 32 00 00 0a 0a 06 6f 33 00 00 0a 0b 73 30 00 00 0a 28 ?? 00 00 0a 72 d6 01 00 70}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAE_2147896428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAE!MTB"
        threat_id = "2147896428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 08 09 9a 13 04 11 04 28 ?? 00 00 0a 23 00 00 00 00 00 ?? ?? ?? 59 28 ?? 00 00 0a b7 13 05 06 11 05 28 ?? 00 00 0a 6f ?? 00 00 0a 26 00 09 17 d6 0d 09 08 8e 69 fe 04 13 06 11 06 2d c2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PTDN_2147898329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PTDN!MTB"
        threat_id = "2147898329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 03 00 00 2b 07 28 ?? 00 00 06 80 06 00 00 04 07 8e 69 8d 1a 00 00 01 13 04 17 13 08}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAF_2147898340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAF!MTB"
        threat_id = "2147898340"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 05 6f ?? 00 00 0a 13 06 00 06 7b ?? 00 00 04 11 06 6f ?? 00 00 0a 13 07 11 07 15 fe 01 13 08 11 08 2c 1c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PTDS_2147898624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PTDS!MTB"
        threat_id = "2147898624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 0c f0 00 00 28 ?? 00 00 06 20 ca e4 00 00 28 ?? 00 00 06 03 28 ?? 00 00 0a 6f 26 00 00 0a 2c 35 08 28 ?? 00 00 0a 28 16 00 00 0a 0d 2b 04}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_L_2147898975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.L!MTB"
        threat_id = "2147898975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {06 13 04 7e ?? 00 00 04 11 04 02 16 02 8e 69 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_L_2147898975_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.L!MTB"
        threat_id = "2147898975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {11 06 11 04 11 07 11 07 08 91 11 07 09 91 d6 ?? ?? ?? ?? ?? 5f 91 06 11 04 91 61 9c 2b 07 13 07}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PTEJ_2147899428_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PTEJ!MTB"
        threat_id = "2147899428"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6f 1c 00 00 0a 28 ?? 00 00 0a 0a 28 ?? 00 00 0a 06 6f 1f 00 00 0a 6f 20 00 00 0a 14 14 6f 21 00 00 0a 26 00 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_NAJ_2147899459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.NAJ!MTB"
        threat_id = "2147899459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {fe 0e 05 00 38 ?? ?? ?? ff 07 14 72 ?? ?? ?? 70 18 8d ?? ?? ?? 01 13 04 11 04 16 14 a2 00 11 04 17 14 a2 00 11 04 14 14 14 17 28 ?? ?? ?? 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Windows.g.resources" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAJ_2147899616_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAJ!MTB"
        threat_id = "2147899616"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 07 02 08 18 5a 18 6f ?? ?? 00 0a 1f 10 28 ?? ?? 00 0a 6f ?? ?? 00 0a 00 00 08 17 58 0c 08 06 fe 04 0d 09 2d da}  //weight: 5, accuracy: Low
        $x_5_2 = {a1 50 79 1f 33 0a bc 39 6e df c6 98 ef bd 2c de 30}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PTET_2147900326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PTET!MTB"
        threat_id = "2147900326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 44 1f 14 1f 2d 28 ?? 00 00 06 2b 1d 06 28 ?? 00 00 06 20 bf 02 00 00 20 b4 02 00 00 28 ?? 00 00 06 0b 07 2c 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PTFU_2147900784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PTFU!MTB"
        threat_id = "2147900784"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {17 02 08 17 28 ?? 00 00 0a 28 ?? 00 00 0a 07 da 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 00 08 17 d6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PTJO_2147903869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PTJO!MTB"
        threat_id = "2147903869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {7e 02 00 00 04 28 ?? 00 00 2b 28 ?? 00 00 2b 13 05 28 ?? 00 00 0a 11 05 6f 1a 00 00 0a 13 06 11 06 28 ?? 00 00 0a 13 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_PTJP_2147904074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.PTJP!MTB"
        threat_id = "2147904074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 1a 00 00 01 13 0a 08 11 0a 16 1a 28 ?? 00 00 06 26 11 0a 16 28 ?? 00 00 06 13 06 73 26 00 00 06 13 08 1b 8d 1a 00 00 01 13 09}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAQ_2147904185_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAQ!MTB"
        threat_id = "2147904185"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 02 08 6f ?? 00 00 0a 1f 30 59 02 08 17 59 6f ?? 00 00 0a 1f 30 59 18 5a 58 02 08 18 59 6f ?? 00 00 0a 1f 30 59 1a 5a 58 02 08 19 59 6f ?? 00 00 0a 1f 30 59 1e 5a 58 0d 06 07 25 17 59 0b 12 03 ?? ?? ?? ?? ?? 28 ?? 00 00 0a 16 6f ?? 00 00 0a 9d 00 08 1a 59 0c}  //weight: 1, accuracy: Low
        $x_1_2 = {19 00 07 08 06 08 9a 28 ?? 00 00 06 1f 10 28 ?? 00 00 0a d2 9c 00 08 17 58 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAR_2147904788_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAR!MTB"
        threat_id = "2147904788"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 11 04 08 11 04 91 09 61 d2 9c 09 20 ?? 00 00 00 5a 20 00 01 00 00 5d d2 0d 11 04 17 58 13 04}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAS_2147904830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAS!MTB"
        threat_id = "2147904830"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 1e 5d 0c 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01 06 d2 61 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_M_2147905451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.M!MTB"
        threat_id = "2147905451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 16 03 04 16 0f ?? 28 ?? 00 00 06 20 b8 0b 00 00 7e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAU_2147905490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAU!MTB"
        threat_id = "2147905490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SiEScYBheaohEnGX4J" wide //weight: 1
        $x_1_2 = "BKIRJxgGF5qiEScZfgk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAV_2147906238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAV!MTB"
        threat_id = "2147906238"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0e 13 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAZ_2147910937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAZ!MTB"
        threat_id = "2147910937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 07 09 91 19 8d ?? 00 00 01 25 d0 ?? 00 00 04 28 ?? 00 00 0a 09 19 5d 91 61 d2 9c 00 09 17 58 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_NT_2147912529_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.NT!MTB"
        threat_id = "2147912529"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 06 09 11 06 16 11 06 8e b7 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 00 28 ?? 00 00 0a 07 6f ?? 00 00 0a 6f ?? 00 00 0a 0c de 10}  //weight: 5, accuracy: Low
        $x_1_2 = "lHZOeqHkqIPpPcmlwKpsDHH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAC_2147912977_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAC!MTB"
        threat_id = "2147912977"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "RUPgR4gDVEYEEAQD" wide //weight: 3
        $x_3_2 = {49 00 67 00 41 00 41 00 52 00 67 00 42 00 41 00 41 00 4d 00 51 00 42 00 64 00 34 00 51 00 41}  //weight: 3, accuracy: High
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "StrReverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_SJPL_2147914953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.SJPL!MTB"
        threat_id = "2147914953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 10 59 0d 06 09 03 08 18 6f 31 00 00 0a 1f 10 28 32 00 00 0a 07 09 07 8e 69 5d 91 61 d2 9c 08 18 58 0c 08 03 6f 30 00 00 0a 32 b6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAA_2147917506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAA!MTB"
        threat_id = "2147917506"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 91 04 8e 69 5d 91 28 ?? 00 00 06 61 04 07 07 1d 5d d6 04 8e 69 5d 04 8e 69 5d 91 61 9c 07 17 d6 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAB_2147917507_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAB!MTB"
        threat_id = "2147917507"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 08 9a 0b 06 07 18 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 01 00 0a 0a 08 17 d6 0c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAI_2147919565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAI!MTB"
        threat_id = "2147919565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 06 8f ?? 00 00 01 25 71 ?? 00 00 01 11 06 0e 04 58 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 1f 0c 13 12}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAJ_2147919566_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAJ!MTB"
        threat_id = "2147919566"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 07 95 58 6e 20 ff 00 00 00 6a 5f 69 95 61 d2 9c 09 17 58 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAM_2147919572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAM!MTB"
        threat_id = "2147919572"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 18}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAF_2147920823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAF!MTB"
        threat_id = "2147920823"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAO_2147921800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAO!MTB"
        threat_id = "2147921800"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 10 13 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAR_2147921807_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAR!MTB"
        threat_id = "2147921807"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 11 05 02 11 05 91 08 61 06 07 91 61 b4 9c 07 03 6f ?? 00 00 0a 17 da fe 01 13 07 11 07 2c 04 16 0b 2b 05 00 07 17 d6 0b 00 11 05 17 d6 13 05 11 05 11 06 13 08 11 08 31 c6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_SARA_2147922106_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.SARA!MTB"
        threat_id = "2147922106"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 11 04 08 6f ?? ?? ?? 0a 00 11 04 04 6f ?? ?? ?? 0a 00 11 04 05 6f ?? ?? ?? 0a 00 11 04 6f ?? ?? ?? 0a 0a 06 02 16 02 8e b7 6f ?? ?? ?? 0a 0d 11 04 6f ?? ?? ?? 0a 00 09 13 05}  //weight: 2, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAS_2147922252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAS!MTB"
        threat_id = "2147922252"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 00 45 00 51 00 39 00 6b 00 32 00 55 00 51 00 41 00 6b 00 67 00 6a 00 76}  //weight: 3, accuracy: High
        $x_4_2 = {62 00 4e 00 37 00 34 00 59 00 7a 00 7a 00 73 00 64 00 37 00 65 00 56 00 32}  //weight: 4, accuracy: High
        $x_5_3 = {39 00 52 00 53 00 58 00 45 00 39 00 38 00 79 00 58 00 6a 00 4c 00 52 00 4b}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_KAAQ_2147924319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.KAAQ!MTB"
        threat_id = "2147924319"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = ",73,78,71,88,88,80,65," ascii //weight: 3
        $x_3_2 = ",73,78,71,88,88,80,65,68,68,7" ascii //weight: 3
        $x_3_3 = "80,65,68,68,73,78,71,80,65," ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_SKBD_2147933732_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.SKBD!MTB"
        threat_id = "2147933732"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0b 11 0e 8f ?? 00 00 01 25 71 ?? 00 00 01 11 05 20 ff 00 00 00 5f d2 61 d2 81 ?? 00 00 01 11 0b 11 0e 17 58 8f ?? 00 00 01 25 71 ?? 00 00 01 11}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_GPPG_2147938492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.GPPG!MTB"
        threat_id = "2147938492"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {09 11 04 91 13 05 00 07 06 11 05 20 05 b9}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_NMK_2147938608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.NMK!MTB"
        threat_id = "2147938608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "FuckCrypt.Resources" ascii //weight: 2
        $x_1_2 = "https://pastebin." ascii //weight: 1
        $x_1_3 = "cyber-password-freepik" ascii //weight: 1
        $x_1_4 = "UpCry\\obj\\Debug\\FuckCrypt.pdb" ascii //weight: 1
        $x_1_5 = "Ati Vmware, VirtualBox" ascii //weight: 1
        $x_1_6 = "[system.Convert]::FromBase64String" ascii //weight: 1
        $x_1_7 = "powershell -ExecutionPolicy Bypass -File" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_ZUT_2147943791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.ZUT!MTB"
        threat_id = "2147943791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 72 a4 00 00 70 0b 06 8e 69 8d ?? 00 00 01 0c 16 0d 38 1a 00 00 00 08 09 06 09 91 07 09 07 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d2 9c 09 17 58 0d 09 06 8e 69 32 e0 08 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_SPEQ_2147954668_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.SPEQ!MTB"
        threat_id = "2147954668"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0b 06 07 28 ?? 00 00 0a 0c 08 72 ?? ?? ?? 70 72 ?? ?? ?? 70 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 14 13 04 11 04 13 05 09 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 14 6f ?? 00 00 0a 13 06 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_SPBR_2147956975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.SPBR!MTB"
        threat_id = "2147956975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {13 05 11 05 09 6f ?? 00 00 0a 11 05 08 6f ?? 00 00 0a 11 05 17 6f ?? 00 00 0a 11 05 18 6f ?? 00 00 0a 73 ?? 00 00 0a 13 06 11 06 11 05 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 07 11 07 06 16 06 8e b7 6f ?? 00 00 0a de 0c 11 07 2c 07 11 07 6f ?? 00 00 0a dc}  //weight: 4, accuracy: Low
        $x_2_2 = {08 09 08 09 91 07 61 9c 09 17 d6 0d 09 11 04 31 ef}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_NjRAT_ZHI_2147959543_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/NjRAT.ZHI!MTB"
        threat_id = "2147959543"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NjRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 02 8e b7 17 59 0c 0b 2b 0d 02 07 02 07 91 1d 61 d2 9c 07 1d 58 0b 07 08 31 ef 02 2a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

