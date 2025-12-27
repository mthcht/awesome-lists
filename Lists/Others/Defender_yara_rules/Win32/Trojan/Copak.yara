rule Trojan_Win32_Copak_CJ_2147813584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CJ!MTB"
        threat_id = "2147813584"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 03 81 c7 [0-4] 43 81 c7 [0-4] 39 d3 75 dd}  //weight: 2, accuracy: Low
        $x_2_2 = {31 01 41 39 f1 75 e5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CK_2147813675_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CK!MTB"
        threat_id = "2147813675"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b 09 db e8 [0-4] 31 07 81 c7 01 00 00 00 39 f7 75 e6}  //weight: 2, accuracy: Low
        $x_2_2 = {31 06 81 c1 [0-4] 29 cf 46 81 e9 [0-4] 81 e9 [0-4] 39 de 75 d8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CB_2147813743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CB!MTB"
        threat_id = "2147813743"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 13 01 f1 81 c3 04 00 00 00 81 c7 [0-4] 39 c3 75 e7}  //weight: 2, accuracy: Low
        $x_2_2 = {31 39 01 c2 41 42 89 c2 39 d9 75 dc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CC_2147813744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CC!MTB"
        threat_id = "2147813744"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 08 29 fe 81 ee [0-4] 40 89 f7 89 f7 39 d8 75 d8}  //weight: 2, accuracy: Low
        $x_2_2 = {89 c8 31 16 46 39 de 75 e5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CG_2147813929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CG!MTB"
        threat_id = "2147813929"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4b 29 df e8 [0-4] 31 02 81 c2 01 00 00 00 39 ca 75 e7}  //weight: 2, accuracy: Low
        $x_2_2 = {01 f6 31 17 81 c7 01 00 00 00 39 c7 75 e0}  //weight: 2, accuracy: High
        $x_2_3 = {21 c8 31 3e 81 c6 01 00 00 00 01 c9 39 d6 75 de}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CH_2147813932_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CH!MTB"
        threat_id = "2147813932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {42 21 d2 31 0b 81 c6 ?? ?? ?? ?? 4a 81 ee}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_CH_2147813932_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CH!MTB"
        threat_id = "2147813932"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 37 89 c3 47 01 db b8 [0-4] 39 d7 75 e6}  //weight: 2, accuracy: Low
        $x_2_2 = {21 df 31 0e 43 09 df 46 4f 29 db 39 d6 75 d9}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CM_2147813955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CM!MTB"
        threat_id = "2147813955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 d3 31 0f 4a 89 d3 47 09 da 39 f7 75 e3}  //weight: 2, accuracy: High
        $x_2_2 = {8b 0c 24 83 c4 04 e8 [0-4] 31 0f 4a 81 c7 01 00 00 00 39 f7 75 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CN_2147814060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CN!MTB"
        threat_id = "2147814060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 1e 01 c0 46 39 fe 75 ed}  //weight: 2, accuracy: High
        $x_2_2 = {31 3a 81 c2 01 00 00 00 29 c0 81 e8 [0-4] 39 ca 75 da}  //weight: 2, accuracy: Low
        $x_2_3 = {31 0a 81 c6 [0-4] 47 42 39 c2 75 d9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CP_2147814249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CP!MTB"
        threat_id = "2147814249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 0a 4b 68 [0-4] 5b 81 c2 01 00 00 00 81 e8 [0-4] 09 c3 39 fa 75 ce}  //weight: 2, accuracy: Low
        $x_2_2 = {31 08 81 ea [0-4] 81 c6 [0-4] 81 c0 01 00 00 00 01 f2 81 ea [0-4] 39 f8 75 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CQ_2147814458_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CQ!MTB"
        threat_id = "2147814458"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 0b 09 d2 81 e8 [0-4] 81 c3 04 00 00 00 81 c2 [0-4] 39 f3 75 e1}  //weight: 2, accuracy: Low
        $x_2_2 = {31 16 09 c8 81 c3 [0-4] 81 c6 04 00 00 00 39 fe 75 e7}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CR_2147814572_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CR!MTB"
        threat_id = "2147814572"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 18 40 39 f8 75 e9}  //weight: 2, accuracy: High
        $x_2_2 = {31 33 81 c3 04 00 00 00 40 09 f8 39 cb 75 ec}  //weight: 2, accuracy: High
        $x_2_3 = {31 06 42 29 ca 46 01 d2 39 fe 75 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_GP_2147815052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GP!MTB"
        threat_id = "2147815052"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4f 09 cf 31 1e 01 f9 81 c7 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 09 c9 81 ef ?? ?? ?? ?? 39 d6 75 d6 b9 ?? ?? ?? ?? 41 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GI_2147815239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GI!MTB"
        threat_id = "2147815239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 10 49 81 c0 04 00 00 00 81 ee ?? ?? ?? ?? 39 d8 75 e8 81 c7 ?? ?? ?? ?? c3 89 f6 bf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GI_2147815239_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GI!MTB"
        threat_id = "2147815239"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 c9 09 d1 39 f0 75 eb c3 ff 74 01 ?? 31 17 81 c7 ?? ?? ?? ?? 01 c0 4e 39 df 75 ec 09 f1 21 f1 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_CU_2147815325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CU!MTB"
        threat_id = "2147815325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {89 da 31 08 40 39 f0 75 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_H_2147815460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.H!MTB"
        threat_id = "2147815460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {29 c9 09 c9 31 32 42 49 89 f9 39 c2 75 e8 01 ff 21 cf c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_P_2147815613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.P!MTB"
        threat_id = "2147815613"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d6 81 ea ?? ?? ?? ?? 4e bf ?? ?? ?? ?? 29 f2 e8 ?? ?? ?? ?? 31 38 81 c0 ?? ?? ?? ?? 39 c8 75 e8 29 d2 81 ee ?? ?? ?? ?? c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_S_2147815689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.S!MTB"
        threat_id = "2147815689"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {d8 85 40 00 29 d2 e8 ?? ?? ?? ?? 31 1e 81 ea ?? ?? ?? ?? 81 c2 ?? ?? ?? ?? 81 c6 ?? ?? ?? ?? 09 c0 81 e8 ?? ?? ?? ?? 39 ce 75 d4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_CX_2147816904_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CX!MTB"
        threat_id = "2147816904"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 38 81 c3 [0-4] 81 c0 04 00 00 00 21 c9 81 c2 [0-4] 39 f0 75 e1}  //weight: 2, accuracy: Low
        $x_2_2 = {29 c1 81 e8 01 00 00 00 e8 [0-4] 31 1e 81 c0 [0-4] 46 39 fe 75 db}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CY_2147817235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CY!MTB"
        threat_id = "2147817235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 08 ba 29 78 5e 5e 81 c0 04 00 00 00 81 eb [0-4] 39 f0 75 e4}  //weight: 2, accuracy: Low
        $x_2_2 = {31 37 29 d0 21 d2 81 c7 04 00 00 00 68 [0-4] 8b 04 24 83 c4 04 01 c2 39 cf 75 de}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CZ_2147817826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CZ!MTB"
        threat_id = "2147817826"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {39 f6 74 01 ea 31 16 81 c6 04 00 00 00 39 fe 75 ef}  //weight: 2, accuracy: High
        $x_2_2 = {31 0e 21 ff 81 c6 04 00 00 00 39 de 75 ed}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_FL_2147818351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.FL!MTB"
        threat_id = "2147818351"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {31 10 81 c0 04 00 00 00 09 db 39 f8 75 ed 46 c3}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_FU_2147818466_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.FU!MTB"
        threat_id = "2147818466"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 03 81 c2 01 00 00 00 81 c1 ?? ?? ?? ?? 43 39 f3}  //weight: 10, accuracy: Low
        $x_10_2 = {29 d2 8b 00 81 ea ?? ?? ?? ?? 81 e0 ff 00 00 00 47 81 ff}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_BB_2147818486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BB!MTB"
        threat_id = "2147818486"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {31 17 4e 81 e9 c1 f2 71 2b 81 c7 04 00 00 00 81 c1 5d 6c 85 cb 39 df 75 e2}  //weight: 3, accuracy: High
        $x_3_2 = {31 3a 81 eb eb f7 9a c4 81 c2 04 00 00 00 89 db 09 d9 39 c2 75 e5}  //weight: 3, accuracy: High
        $x_2_3 = {89 ff 09 ff 46 89 f8 89 f8 81 fe 84 27 00 01 75 bd}  //weight: 2, accuracy: High
        $x_2_4 = {81 c6 01 00 00 00 81 c3 36 d5 b8 e3 21 c9 21 cb 81 fe ec 56 00 01 75 c0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Copak_FV_2147818684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.FV!MTB"
        threat_id = "2147818684"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {68 d8 85 40 00 58 e8 ?? ?? ?? ?? 01 c9 b9 ?? ?? ?? ?? 31 06 81 c6 ?? ?? ?? ?? 39 d6 75 e2 83 ec 04 89 3c 24 8b 0c 24 83 c4 04}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_BE_2147819293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BE!MTB"
        threat_id = "2147819293"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {31 32 29 c8 41 81 c2 04 00 00 00 01 c9 41 39 da 75 e9}  //weight: 3, accuracy: High
        $x_3_2 = {31 1e 40 81 c6 04 00 00 00 09 c0 21 f8 39 ce 75 ea}  //weight: 3, accuracy: High
        $x_2_3 = {8b 0c 24 83 c4 04 42 21 ff b9 67 73 cd 7e 81 fa 29 ed 00 01 75 c3}  //weight: 2, accuracy: High
        $x_2_4 = {01 c1 81 c7 01 00 00 00 81 c1 b4 65 11 c1 49 81 ff 38 46 00 01 75 bc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Copak_VU_2147819647_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.VU!MTB"
        threat_id = "2147819647"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 c0 29 c0 e8 ?? ?? ?? ?? 81 e8 ?? ?? ?? ?? 29 db 31 0e 09 db 46 29 c3 39 d6 75 df 21 db}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_VZ_2147819976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.VZ!MTB"
        threat_id = "2147819976"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 38 f7 d2 f7 d2 81 e7 ?? ?? ?? ?? 4a 09 d3 89 ca 31 3e 42 21 da f7 d2 81 c6 ?? ?? ?? ?? 29 ca 81 eb ?? ?? ?? ?? 21 d9 40 f7 d3 09 c9 81 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_BH_2147820242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BH!MTB"
        threat_id = "2147820242"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {39 d2 74 01 ea 31 18 be 92 75 3c 39 81 c2 54 1f b0 10 81 c0 04 00 00 00 01 d2 39 c8 75 e2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DC_2147821407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DC!MTB"
        threat_id = "2147821407"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 ff 74 01 ea 31 16 29 df 81 c0 11 f9 d0 8d 81 c6 04 00 00 00 bf 7c 6f a7 29 39 ce 75}  //weight: 1, accuracy: High
        $x_1_2 = {29 ff 58 46 89 f6 81 c2 01 00 00 00 01 f7 81 fa 70 a6 00 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DD_2147821577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DD!MTB"
        threat_id = "2147821577"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 c1 b3 77 48 c0 31 3a 51 5b 81 eb 6b 35 16 0e 42 39 f2 75}  //weight: 2, accuracy: High
        $x_2_2 = {81 c2 ff b0 17 38 31 0f 01 d2 47 39 f7 75}  //weight: 2, accuracy: High
        $x_3_3 = {81 eb a1 f8 7d 3c 81 c3 4e be 5f ff 42 81 c7 83 c1 0b 94 81 fa 4c ac 00 01 75}  //weight: 3, accuracy: High
        $x_3_4 = {21 c0 81 e8 a3 be 3d 59 47 89 c0 81 ff 93 6a 00 01 75}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Copak_DE_2147821818_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DE!MTB"
        threat_id = "2147821818"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 16 09 c0 89 c3 46 29 c0 83 ec 04 89 04 24 5b 39 fe 75 db}  //weight: 2, accuracy: High
        $x_2_2 = {09 db 31 01 89 d3 09 db 41 81 eb a9 9d c2 7c 39 f1 75 e1}  //weight: 2, accuracy: High
        $x_2_3 = {01 d2 81 ea 01 00 00 00 31 30 40 39 d8 75 e7}  //weight: 2, accuracy: High
        $x_3_4 = {29 fe 43 21 ff 21 f6 4f 81 fb c4 cc 00 01 75 bc}  //weight: 3, accuracy: High
        $x_3_5 = {21 db 81 c6 01 00 00 00 89 de 58 21 f3 42 46 81 fa cf 7b 00 01 75 bf}  //weight: 3, accuracy: High
        $x_3_6 = {29 f0 81 c1 01 00 00 00 81 c6 f6 62 48 ed 01 c6 81 f9 29 48 00 01 75 b1}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Copak_DF_2147821985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DF!MTB"
        threat_id = "2147821985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {39 d2 74 01 ea 31 02 01 f1 81 c2 04 00 00 00 39 fa 75 ed}  //weight: 1, accuracy: High
        $x_1_2 = {52 51 58 29 c8 5f 40 43 21 c9 81 fb 94 12 00 01 75 b2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DG_2147824237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DG!MTB"
        threat_id = "2147824237"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 1f 68 5d 37 18 d7 5e 81 c7 04 00 00 00 29 c1 81 ee 02 5f 26 7a 39 d7 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DH_2147824705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DH!MTB"
        threat_id = "2147824705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 03 81 c3 04 00 00 00 47 81 ef 25 b1 6a 9b 39 cb 75}  //weight: 1, accuracy: High
        $x_1_2 = {43 01 ff 29 c7 21 ff 81 fb 8f bc 00 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DI_2147826058_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DI!MTB"
        threat_id = "2147826058"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c6 c4 a0 f4 6c 31 11 50 5e 81 e8 4e 04 d1 c2 81 c1 01 00 00 00 21 f6 39 f9 75}  //weight: 1, accuracy: High
        $x_1_2 = {89 cf 43 81 e9 f5 13 37 11 01 ff 81 fb ee 8e 00 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_B_2147829375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.B!MTB"
        threat_id = "2147829375"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 01 ea 31 02 81 e9 ?? ?? ?? ?? 81 c2 04 00 00 00 21 d9 41 39 fa 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GUF_2147833523_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GUF!MTB"
        threat_id = "2147833523"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 13 41 01 ff 81 c3 04 00 00 00 39 c3 75 ec 81 c7 ?? ?? ?? ?? 01 f1 c3}  //weight: 10, accuracy: Low
        $x_10_2 = {31 3e 81 c6 04 00 00 00 49 49 39 c6 75 ed c3 14 40 00 c3 39 c9 74}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_GTF_2147835985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GTF!MTB"
        threat_id = "2147835985"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {bf d8 85 40 00 81 e8 ?? ?? ?? ?? e8 ?? ?? ?? ?? 01 c0 31 39 81 c6 ?? ?? ?? ?? 09 c0 81 c1 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 39 d1 75}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RDA_2147836249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RDA!MTB"
        threat_id = "2147836249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 30 43 53 5b 40 81 eb 61 0a f8 a1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RDA_2147836249_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RDA!MTB"
        threat_id = "2147836249"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {56 4a 8b 3c 24 83 c4 04 81 eb 01 00 00 00 57 21 da 21 d3 81 c2 45 c3 af b0 8b 0c 24 83 c4 04 01 da 81 c2 9f ea 88 a8 51 29 d2 43 8b 34 24 83 c4 04 81 ea 01 00 00 00 81 c2 21 57 ea 16 ba 8d 69 56 7f 40 09 db 81 f8 09 40 00 01}  //weight: 2, accuracy: High
        $x_2_2 = {93 b6 81 c1 04 00 00 00 39 d9 75 e9 89 f8 c3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_BAG_2147837981_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BAG!MTB"
        threat_id = "2147837981"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 c9 31 1a 89 c1 b9 c4 01 20 5a 42 81 e8 01 00 00 00 01 c9 39 f2 75}  //weight: 2, accuracy: High
        $x_2_2 = {5a 81 c3 f0 87 c6 7d 89 f3 81 c7 01 00 00 00 81 ee 20 f6 88 bc 21 f6 09 db 81 ff 5c 00 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DB_2147842261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DB!MTB"
        threat_id = "2147842261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {29 f6 21 f7 e8 [0-4] 01 fe 31 19 81 c1 01 00 00 00 39 c1 75 e4}  //weight: 2, accuracy: Low
        $x_2_2 = {89 c0 8b 0c 24 83 c4 04 09 c0 09 c3 01 d8 42 01 db 81 fa 4e 80 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DK_2147843782_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DK!MTB"
        threat_id = "2147843782"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 1a 21 c9 81 e9 01 00 00 00 81 c2 02 00 00 00 29 c0 29 c8 09 c0 39 fa 7c}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 04 21 fe 4f 43 81 ee 01 00 00 00 68 5a bc 21 87 5e 01 ff 81 fb a7 33 00 01 75 b5}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DL_2147843783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DL!MTB"
        threat_id = "2147843783"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {29 df 31 06 81 c7 01 00 00 00 bf e9 77 50 b1 68 1d e3 b7 6e 5f 81 c6 01 00 00 00 29 df 81 eb 86 e9 cc e0 21 fb 39 d6 75}  //weight: 2, accuracy: High
        $x_2_2 = {83 ec 04 89 1c 24 5f 8b 0c 24 83 c4 04 bb 2b c1 5e 82 46 21 df 81 c7 01 00 00 00 81 fe 60 06 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DM_2147843819_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DM!MTB"
        threat_id = "2147843819"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {01 c7 81 c7 67 61 97 c3 e8 [0-4] 09 c7 b8 74 e0 d1 53 31 16 09 f8 81 c6 01 00 00 00 50 5f 39 de 75}  //weight: 2, accuracy: Low
        $x_2_2 = {5a 09 db 81 c7 d3 4e 1e 83 40 01 db 47 47 81 f8 fe e6 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GHC_2147843849_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GHC!MTB"
        threat_id = "2147843849"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 16 81 c6 ?? ?? ?? ?? 01 c9 39 de 75 ed}  //weight: 10, accuracy: Low
        $x_10_2 = {31 19 81 ef ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 4e 81 c6 ?? ?? ?? ?? 39 c1 75 e2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_DN_2147844019_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DN!MTB"
        threat_id = "2147844019"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {01 db 43 31 01 89 de 01 f6 41 83 ec 04 89 34 24 8b 1c 24 83 c4 04 39 d1 75}  //weight: 2, accuracy: High
        $x_2_2 = {29 d3 81 c2 1d 39 57 7c 8b 04 24 83 c4 04 81 c2 01 00 00 00 21 db 4a 46 89 db 81 fe b5 26 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GHG_2147844051_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GHG!MTB"
        threat_id = "2147844051"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 ea 31 3b 81 c0 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 40 39 cb 75 e8 c3 c3 81 e9 ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 39 ff 74}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GHI_2147844072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GHI!MTB"
        threat_id = "2147844072"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 0f 21 f6 4b 81 c7 ?? ?? ?? ?? 89 db 81 c3 ?? ?? ?? ?? 39 c7 75 ?? 42 81 eb ?? ?? ?? ?? c3 89 d6 7f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DO_2147844090_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DO!MTB"
        threat_id = "2147844090"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {68 77 fa ca e7 5b 43 31 3e bb 80 23 d9 27 46 81 e8 01 00 00 00 09 c3 29 db 39 ce 75}  //weight: 2, accuracy: High
        $x_2_2 = {29 c0 5f 81 c0 12 76 98 2e 46 89 db 68 89 2a b2 d6 8b 04 24 83 c4 04 81 eb 60 c4 30 df 81 fe bf 8d 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_MA_2147844097_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.MA!MTB"
        threat_id = "2147844097"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 c1 01 00 00 00 01 f9 01 c9 b8 d8 85 40 00 e8 19 00 00 00 31 06 81 c7 01 00 00 00 49 46 21 cf 39 de 75 e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_MB_2147844104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.MB!MTB"
        threat_id = "2147844104"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 c8 68 d8 85 40 00 5a e8 1e 00 00 00 31 13 81 e9 0b 3a 89 5d 43 01 c0 81 c0 01 00 00 00 39 f3 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_MC_2147844112_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.MC!MTB"
        threat_id = "2147844112"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 8b 3c 24 83 c4 04 81 c3 ?? ?? ?? ?? 01 d9 29 d9 e8 ?? ?? ?? ?? 21 d9 49 81 eb 03 1b 85 47 31 38 81 c1 0f 12 c1 60 40 21 cb 09 cb 39 f0 75}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DP_2147844212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DP!MTB"
        threat_id = "2147844212"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 ec 04 89 14 24 8b 34 24 83 c4 04 31 3b 89 f6 be ca ac 7f fe 43 39 c3 75}  //weight: 2, accuracy: High
        $x_2_2 = {83 c4 04 81 c3 ba fe 0a e5 46 81 ea dc a0 ae 39 68 5f b4 1b 06 5a 01 d2 81 fe c2 5f 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_ME_2147844215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.ME!MTB"
        threat_id = "2147844215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {41 81 c7 58 54 ed 46 81 ef 1d 7f 5d 19 68 d8 85 40 00 5b 81 e9 c9 15 e4 85 09 f9 e8 16 00 00 00 31 1a 68 4c 27 fc d9 59 42 81 e9 28 ef 66 11 39 f2 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DQ_2147844217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DQ!MTB"
        threat_id = "2147844217"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8b 1a 81 e9 59 5c 36 5f 4f 81 e3 ff 00 00 00 46 29 fe 31 18 4f 47 40 f7 d1 47 81 c2 01 00 00 00 89 cf 09 ff 81 ef 1d e2 70 fc 81 f8 b8 af 47 00 0f}  //weight: 2, accuracy: High
        $x_2_2 = {8b 3e 4b 09 c8 81 e7 ff 00 00 00 01 c3 f7 d3 21 d8 31 3a 89 d8 41 42 09 db 48 46 81 c1 0a 05 d9 3d 81 c3 34 a9 b3 d4 81 fa b8 af 47 00 0f}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_DR_2147844299_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DR!MTB"
        threat_id = "2147844299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c1 f2 b6 21 03 81 c0 9f e8 0e eb e8 [0-4] 81 c1 2a 21 91 32 31 33 43 39 d3 75}  //weight: 2, accuracy: Low
        $x_2_2 = {21 d2 01 d1 81 c1 31 6f fc 73 5e 09 ca 29 d2 47 29 d1 4a 09 ca 81 ff 4e cc 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DR_2147844299_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DR!MTB"
        threat_id = "2147844299"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 d6 81 e2 ff 00 00 00 f7 d0 b8 24 77 f9 44 31 11 81 c0 f1 d6 28 f7 81 c3 67 c7 45 6c 21 de 81 c1 01 00 00 00 89 f3 be 0b a1 0b a8 47 81 eb dd 9c 8a 58 21 c3 09 db 81 f9 b8 af 47 00 0f}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_MD_2147844368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.MD!MTB"
        threat_id = "2147844368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4d 5a 95 5c 39 15 f9 a6 bd 15 0d a5 3f 89 22 89 3b 22 22 f9 22 22 15 15 12 5c 15 22 15 15 15 2d 15 22 15 22 bf 22 22 c1 3f 3f 22 6d 22 15 8d 15 15}  //weight: 5, accuracy: High
        $x_5_2 = {3f 0d 6d 15 3f 22 6d 3f 76 15 22 80 00 00 00 0e 1f ba 0e 00 b4 09 cd 21 b8 01 4c cd 21 54 68 69 73 20 70 72 6f 67 72 61 6d 20 63 61 6e 6e 6f}  //weight: 5, accuracy: High
        $x_5_3 = {e0 00 0f 03 0b 01 03 04 c0 78 00 00 00 cc 00 00 20 69 01 00 d8 85}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_MF_2147844459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.MF!MTB"
        threat_id = "2147844459"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {81 c1 8f 97 a1 c2 ba d8 85 40 00 09 c9 e8 1f 00 00 00 29 c8 31 13 09 c8 81 c0 34 cd ca 66 81 c3 01 00 00 00 39 fb 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GHM_2147844551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GHM!MTB"
        threat_id = "2147844551"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {89 14 24 8b 14 24 83 c4 04 e8 ?? ?? ?? ?? 01 f2 81 c2 ?? ?? ?? ?? 31 19 81 c1 ?? ?? ?? ?? 39 c1 75 ?? 81 ea}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GHN_2147844630_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GHN!MTB"
        threat_id = "2147844630"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 31 bf 7f 98 84 7f 42 81 c1 ?? ?? ?? ?? 39 d9 75 e9 09 fa 01 c2 c3 81 ef ?? ?? ?? ?? 96 0d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GIA_2147845856_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GIA!MTB"
        threat_id = "2147845856"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5a 31 38 81 c2 01 00 00 00 21 db 40 01 d3 81 eb ?? ?? ?? ?? 39 c8 75 cd c3 01 db 8d 3c 3e 81 c3 ?? ?? ?? ?? 01 d2 8b 3f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GIB_2147845876_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GIB!MTB"
        threat_id = "2147845876"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {09 ff 42 e8 ?? ?? ?? ?? 52 5f 31 30 21 d7 40 81 c7 ?? ?? ?? ?? 81 ef ?? ?? ?? ?? 39 c8 75}  //weight: 10, accuracy: Low
        $x_10_2 = {09 df 83 ec 04 c7 04 24 ?? ?? ?? ?? 58 e8 ?? ?? ?? ?? 31 02 81 c2 01 00 00 00 01 db 39 f2 75 ?? 89 df}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_GIC_2147845955_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GIC!MTB"
        threat_id = "2147845955"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {b8 0d 5d 42 9e 31 1f 47 50 8b 04 24 83 c4 04 89 c1 39 f7 75 dc 81 e9 ?? ?? ?? ?? 89 c0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DS_2147847840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DS!MTB"
        threat_id = "2147847840"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {81 e9 ed b4 1e 4e 31 30 81 e9 01 00 00 00 40 83 ec 04 89 3c 24 5f 01 ff 39 d0 75}  //weight: 2, accuracy: High
        $x_2_2 = {8b 14 24 83 c4 04 8b 34 24 83 c4 04 09 c0 4a 81 e8 24 0e aa b8 47 21 d2 81 ff 4a e1 00 01 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GJK_2147847870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GJK!MTB"
        threat_id = "2147847870"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {81 e9 82 f9 e9 71 31 10 b9 ac b2 04 24 40 46 39 f8 75 ?? 21 c9 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RG_2147848054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RG!MTB"
        threat_id = "2147848054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 19 50 8b 04 24 83 c4 04 41 39 f9 75 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RH_2147848055_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RH!MTB"
        threat_id = "2147848055"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fa f4 01 00 00 75 05 ba 00 00 00 00 c3 2b e2 58 68 4e 3f 3e de 5f c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GJL_2147848096_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GJL!MTB"
        threat_id = "2147848096"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5a 01 f8 e8 ?? ?? ?? ?? 01 ff bf ?? ?? ?? ?? 31 11 41 21 ff 83 ec 04 89 3c 24 5f 39 f1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GJM_2147848370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GJM!MTB"
        threat_id = "2147848370"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? c3 09 c9 bb ?? ?? ?? ?? e8 ?? ?? ?? ?? 31 1a 42 81 ef ?? ?? ?? ?? 81 e9 ?? ?? ?? ?? 39 f2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_DT_2147848548_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.DT!MTB"
        threat_id = "2147848548"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {81 ea de a1 d9 83 e8 [0-4] 31 1f 47 81 ea 01 00 00 00 39 cf 75}  //weight: 5, accuracy: Low
        $x_5_2 = {81 eb 01 00 00 00 e8 [0-4] 81 c3 88 ea fe 2b 31 17 21 c3 48 47 81 eb cf de 06 04 09 c3 39 cf 75}  //weight: 5, accuracy: Low
        $x_5_3 = {29 f6 81 ee 28 da 95 bc e8 [0-4] 89 f6 21 f7 31 02 29 fe 29 fe 42 39 ca 75}  //weight: 5, accuracy: Low
        $x_5_4 = {31 31 81 e8 aa 5c 98 ac 01 c0 81 c1 01 00 00 00 29 ff 39 d9 75}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_GJT_2147848933_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GJT!MTB"
        threat_id = "2147848933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 13 01 f8 21 ff 43 4f 81 c7 ?? ?? ?? ?? 81 c0 ?? ?? ?? ?? 39 f3 75 ?? 21 f8 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GJT_2147848933_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GJT!MTB"
        threat_id = "2147848933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 59 81 c1 ?? ?? ?? ?? 31 1f 47 81 c1 ?? ?? ?? ?? 39 d7 75 ?? c3 81 c6 ?? ?? ?? ?? 8d 1c 03}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GJT_2147848933_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GJT!MTB"
        threat_id = "2147848933"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 34 24 83 c4 ?? e8 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 83 ec ?? 89 14 24 5a 31 37 21 da 47 81 ea ?? ?? ?? ?? 29 db 39 cf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_CRTD_2147849626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CRTD!MTB"
        threat_id = "2147849626"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {40 31 0a 29 c7 09 f8 42 39 f2 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_A_2147849983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.A!MTB"
        threat_id = "2147849983"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 1a 42 21 f6 39 ca 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RL_2147850570_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RL!MTB"
        threat_id = "2147850570"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 ce 00 81 ea 4b ff c1 d3 c3 01 d7 81 c7 18 ae 63 93 00 00 81 fb f4 01 00 00 75 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RM_2147850571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RM!MTB"
        threat_id = "2147850571"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 d2 09 c9 b9 8f ff 92 9a 01 00 00 75 05 bb 00 00 00 00 40 89 c0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GNB_2147850652_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GNB!MTB"
        threat_id = "2147850652"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d2 09 d2 e8 ?? ?? ?? ?? 42 81 c1 ?? ?? ?? ?? 31 07 47 89 d2 21 c9 39 df}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GNE_2147850664_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GNE!MTB"
        threat_id = "2147850664"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 c9 21 f9 e8 ?? ?? ?? ?? 01 ff 21 cf 31 13 21 c9 bf ?? ?? ?? ?? 21 f9 43 21 ff 39 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GNI_2147851182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GNI!MTB"
        threat_id = "2147851182"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 1a 81 c2 ?? ?? ?? ?? 68 ?? ?? ?? ?? 5e 81 c0 ?? ?? ?? ?? 39 ca 75 ?? c3 21 c0 29 c6 8d 1c 1f 8b 1b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RC_2147851540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RC!MTB"
        threat_id = "2147851540"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 04 03 01 f7 8b 00 89 f7 81 e0 ff 00 00 00 09 f7 43 81 c6 ba 60 9e d3 89 f7 81 fb f4 01 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_C_2147852308_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.C!MTB"
        threat_id = "2147852308"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 33 09 c0 42 81 c3 ?? ?? ?? ?? 29 d0 81 e8 ?? ?? ?? ?? 39 fb 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAB_2147852437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAB!MTB"
        threat_id = "2147852437"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 08 f7 d6 81 c7 ?? ?? ?? ?? 81 e1 ?? ?? ?? ?? 09 ff 21 f6 31 0a 01 df 89 df 01 f3 42 89 de 21 fe 81 c0 ?? ?? ?? ?? 4f 09 fe 81 fa}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_AMAB_2147888786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.AMAB!MTB"
        threat_id = "2147888786"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 1a f7 d7 09 c9 81 e3 ?? ?? ?? ?? 21 f6 f7 d7 31 18 21 c9 46 01 cf 81 c0 01 00 00 00 29 cf 89 ce 81 c1 ?? ?? ?? ?? 42 01 c9 f7 d6 f7 d6 81 f8 ?? ?? ?? ?? 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_AMAA_2147890141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.AMAA!MTB"
        threat_id = "2147890141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 3e 81 eb 01 00 00 00 89 da 81 eb ?? ?? ?? ?? 81 e7 ff 00 00 00 21 d1 09 ca 31 38 81 eb ?? ?? ?? ?? f7 d2 40 09 d3 01 d1 09 d2 46 89 d9 81 c2 ?? ?? ?? ?? 29 d3 81 f8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GME_2147891305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GME!MTB"
        threat_id = "2147891305"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5f 21 d9 e8 ?? ?? ?? ?? 43 09 d9 31 38 49 40 81 e9 ?? ?? ?? ?? 29 cb 49 39 f0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAE_2147891723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAE!MTB"
        threat_id = "2147891723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {39 ff 74 01 ea 31 02 81 c2 ?? ?? ?? ?? 09 de 39 fa 75 ed}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAH_2147892124_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAH!MTB"
        threat_id = "2147892124"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 17 81 e9 ?? ?? ?? ?? 4e 21 de 81 e2 ?? ?? ?? ?? 41 89 f3 21 ce 31 10 21 c9 01 db 40 01 f3 29 de 09 de 47 01 f6 29 f3 29 d9 81 f8}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_MBKO_2147894397_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.MBKO!MTB"
        threat_id = "2147894397"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c6 01 8d 43 01 89 c3 3b 5d bc 76 05 bb 01 00 00 00 b8 ?? ?? ?? ?? 8d 7e 01 ba ?? ?? ?? ?? 8a 44 38 ff 8a 54 1a ff 30 c2 8b 7d c0 8d 04 37 88 10 39 f1 77}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPDT_2147894401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPDT!MTB"
        threat_id = "2147894401"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 1a 01 c1 21 c0 89 f8 81 e3 ff 00 00 00 41 81 c7 f0 ec 13 20 31 1e 29 f9 81 e8 a9 ed 2c a8 81 c6 01 00 00 00 01 f8 09 c9 f7 d0 42 81 c7 01 00 00 00 21 c0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAN_2147894423_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAN!MTB"
        threat_id = "2147894423"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 33 01 d2 89 c2 f7 d0 81 e6 ?? ?? ?? ?? 21 c2 21 ca 81 ea ?? ?? ?? ?? 31 37 41 29 d0 47 48 89 c1 43 21 d1 f7 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPDR_2147894625_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPDR!MTB"
        threat_id = "2147894625"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c 24 83 c4 04 21 f7 e8 ?? ?? ?? ?? 31 0a 46 4f 42 bf ?? ?? ?? ?? 29 fe 39 da 75 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPGT_2147894956_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPGT!MTB"
        threat_id = "2147894956"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {8b 1c 24 83 c4 04 29 c9 e8 ?? ?? ?? ?? 29 cf 31 1a 81 ef ?? ?? ?? ?? 4f 81 c2 01 00 00 00 01 c9 21 cf 39 f2 75}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPGY_2147894959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPGY!MTB"
        threat_id = "2147894959"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b9 ca 9f 4c 00 21 c0 01 f0 be 28 ef a9 39 e8 2b 00 00 00 81 c0 b8 0d a0 7a 21 c6 81 ee 53 7e b6 31 31 0a 40 be c4 75 bb 56 29 c0 42 89 c6 81 c6 c4 1c 9e c9 39 fa 75 c8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RF_2147895081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RF!MTB"
        threat_id = "2147895081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 a0 36 4b 00 c3 [0-9] 52 ca 4e 00 [0-48] 31}  //weight: 1, accuracy: Low
        $x_1_2 = {09 f6 c3 09 db 21 f3 81 eb f2 ce 6b ed}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RF_2147895081_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RF!MTB"
        threat_id = "2147895081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {96 87 a7 00 [0-21] 8a 89 a7 00 [0-64] 31 [0-53] ac 89 a7 00 0f 8c ?? ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "htoMvLAa" ascii //weight: 1
        $x_1_3 = "ZzKHIEoMg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GNT_2147895105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GNT!MTB"
        threat_id = "2147895105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 06 46 42 01 d3 39 fe ?? ?? c3 8d 04 08 21 d3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GNT_2147895105_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GNT!MTB"
        threat_id = "2147895105"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 c2 29 d2 31 31 b8 ?? ?? ?? ?? 29 c2 81 c1 ?? ?? ?? ?? 39 f9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GNU_2147895325_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GNU!MTB"
        threat_id = "2147895325"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 3a 81 c2 04 00 00 00 81 c1 ?? ?? ?? ?? 41 39 da ?? ?? 09 c0 41 c3}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_AMMA_2147895544_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.AMMA!MTB"
        threat_id = "2147895544"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 c7 01 00 00 00 31 10 bb ?? ?? ?? ?? 21 ff 68 ?? ?? ?? ?? 5f 81 c0 01 00 00 00 4b 81 c3 ?? ?? ?? ?? 39 f0}  //weight: 2, accuracy: Low
        $x_2_2 = {8d 14 0a 81 c3 ?? ?? ?? ?? 47 81 eb ?? ?? ?? ?? 8b 12 09 df 81 eb ?? ?? ?? ?? 29 ff 81 e2 ff 00 00 00 4f 53 5b 83 ec 04 c7 04 24 ?? ?? ?? ?? 5f 81 c1 01 00 00 00 09 db 81 f9 f4 01 00 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAP_2147895784_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAP!MTB"
        threat_id = "2147895784"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 01 01 d3 01 de 81 e0 ?? ?? ?? ?? f7 d3 81 ee ?? ?? ?? ?? be ?? ?? ?? ?? 31 07 21 d2 21 db 47 4b 4b 4e 41 01 f6 4a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_D_2147895869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.D!MTB"
        threat_id = "2147895869"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 37 47 89 ca 39 c7 0c 00 be ?? ?? ?? ?? 09 d1 e8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_E_2147895875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.E!MTB"
        threat_id = "2147895875"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {31 32 01 df 01 df 81 c2 ?? ?? ?? ?? 89 db 39 c2}  //weight: 2, accuracy: Low
        $x_2_2 = {31 03 41 43 21 d2 21 ca 39 f3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_SPDX_2147895909_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPDX!MTB"
        threat_id = "2147895909"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 1a 40 89 c7 01 c6 81 e3 ff 00 00 00 f7 d6 01 f7 81 ee 62 79 63 11 31 19 81 ef b9 36 73 9d 29 f8 81 e8 1f b4 e4 ce 41 09 f8 09 fe 42 89 c6 89 c7 81 f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPDL_2147895920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPDL!MTB"
        threat_id = "2147895920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 0e 68 90 04 dc f9 8b 1c 24 83 c4 04 81 c6 04 00 00 00 39 fe 75 e4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RJ_2147895946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RJ!MTB"
        threat_id = "2147895946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 fa f4 01 00 00 75 05 ba 00 00 00 00 81 c7 01 00 00 00 c3 09 f7 81 c7 01 00 00 00 eb c5 b0 01 df c3 09 fb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RK_2147895947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RK!MTB"
        threat_id = "2147895947"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {21 df 68 c3 94 1f 9f 5b b9 00 00 00 00 89 d7 c3 89 fa 00 75 05 bb 00 00 00 00 40 89 c0 c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPDS_2147896263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPDS!MTB"
        threat_id = "2147896263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ba 14 8a 43 00 46 01 c9 e8 ?? ?? ?? ?? 29 f1 01 f1 31 10 09 f6 40 89 f1 46 81 ee 4f 51 ca 52 39 f8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAK_2147896277_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAK!MTB"
        threat_id = "2147896277"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 06 21 ff 29 ca 81 e0 ?? ?? ?? ?? b9 ?? ?? ?? ?? bf ?? ?? ?? ?? 31 03 81 e9 ?? ?? ?? ?? bf ?? ?? ?? ?? 43 81 c7 ?? ?? ?? ?? bf ?? ?? ?? ?? 46 01 d7 81 ef}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAO_2147896427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAO!MTB"
        threat_id = "2147896427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 30 01 db 81 c0 ?? ?? ?? ?? 09 fb 09 ff 39 c8 75 dc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAQ_2147896573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAQ!MTB"
        threat_id = "2147896573"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {47 21 f8 31 11 29 c0 01 ff 81 ef ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 09 ff 39 d9 75 d0}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GMC_2147896854_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GMC!MTB"
        threat_id = "2147896854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 31 4a ba f3 5b 16 11 41 21 d2 81 c0 ?? ?? ?? ?? 39 d9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GMC_2147896854_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GMC!MTB"
        threat_id = "2147896854"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 ec 04 c7 04 24 ?? ?? ?? ?? 5f 48 29 d0 09 c2 e8 ?? ?? ?? ?? 21 d2 29 d0 21 c2 31 3e}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPDV_2147896914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPDV!MTB"
        threat_id = "2147896914"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {bf d8 85 40 00 e8 ?? ?? ?? ?? b8 9b e8 34 0f be e8 17 22 f4 31 3a 89 c6 42 56 58 39 da 75 e1}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPE_2147897621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPE!MTB"
        threat_id = "2147897621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {b8 d8 85 40 00 e8 ?? ?? ?? ?? 09 f6 42 31 03 4e 01 d2 43 01 d2 39 cb 75 e7}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPRR_2147898313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPRR!MTB"
        threat_id = "2147898313"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {68 14 8a 43 00 5b 01 c0 e8 26 00 00 00 41 41 29 c1 31 1e 48 46 81 e8 01 00 00 00 81 e9 01 00 00 00 51 8b 04 24 83 c4 04 39 d6 75 d4}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAR_2147898641_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAR!MTB"
        threat_id = "2147898641"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 13 89 ce 29 cf 81 e2 ?? ?? ?? ?? 29 f9 89 fe 46 31 10 29 cf 01 f6 40 47 29 f9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_ACO_2147898752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.ACO!MTB"
        threat_id = "2147898752"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0c 48 8b 5a 96 14 dd d9 8f b9 ?? ?? ?? ?? 86 c8 67 80 11 7b af 87 75 4d 83 d9 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAS_2147898824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAS!MTB"
        threat_id = "2147898824"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {4f 09 f7 31 03 81 ef ?? ?? ?? ?? 81 c7 ?? ?? ?? ?? 29 f6 43 29 fe 81 c7 01 00 00 00 39 cb 75 ce}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GAF_2147899230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GAF!MTB"
        threat_id = "2147899230"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {21 df 31 08 09 df 09 ff 81 c0 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 81 c3 ?? ?? ?? ?? 39 d0}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GAN_2147899738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GAN!MTB"
        threat_id = "2147899738"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 d6 29 f6 e8 ?? ?? ?? ?? 09 f2 31 39 81 ee ?? ?? ?? ?? 81 ee ?? ?? ?? ?? 81 ea ?? ?? ?? ?? 41 09 d2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAT_2147899855_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAT!MTB"
        threat_id = "2147899855"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {31 0b 81 c3 ?? ?? ?? ?? 39 fb 75 ef}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_NC_2147900113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.NC!MTB"
        threat_id = "2147900113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {41 4b 8b 3c 24 83 c4 04 81 ea ?? ?? ?? ?? 21 db 8b 34 24}  //weight: 3, accuracy: Low
        $x_3_2 = {83 c4 04 e8 28 00 00 00 09 db 89 ca 8b 3c 24 83 c4 ?? 81 eb 01 00 00 00 5e 09 d3 21 db}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_NC_2147900113_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.NC!MTB"
        threat_id = "2147900113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {8d 3c 3b 8b 3f 21 c0 81 e7 ?? ?? ?? ?? 89 d0 43 42 21 c2 81 fb f4 01 00 00 75 05}  //weight: 3, accuracy: Low
        $x_3_2 = {81 ee 45 af a2 a7 81 c3 ?? ?? ?? ?? db 81 c1 01 00 00 00 21 db 89 db 81 f9 f4}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_NC_2147900113_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.NC!MTB"
        threat_id = "2147900113"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 30 00 00 00 bf ee 4f eb e4 01 fe 31 03 81 ee ?? ?? ?? ?? 81 c6 64 92 78 96 81 c3 ?? ?? ?? ?? 09 fe 39 d3 75 c8}  //weight: 5, accuracy: Low
        $x_5_2 = {81 c2 01 00 00 00 81 eb ?? ?? ?? ?? 81 ef 40 6c dd 10 81 fa ?? ?? ?? ?? 75 05 ba 00 00 00 00 09 fb 81 eb}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GNF_2147900204_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GNF!MTB"
        threat_id = "2147900204"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {31 32 01 d9 81 c2 04 ?? ?? ?? 81 c3 ?? ?? ?? ?? 39 c2}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GMA_2147900273_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GMA!MTB"
        threat_id = "2147900273"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {c3 44 81 c2 ?? ?? ?? ?? 31 39 b8 b5 f8 d6 15 41 81 e8 ?? ?? ?? ?? 48 39 f1}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_CCGJ_2147900379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CCGJ!MTB"
        threat_id = "2147900379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 f1 29 f6 31 3a 09 c9 42 09 c9 01 f1 39 da 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_CCGK_2147900387_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CCGK!MTB"
        threat_id = "2147900387"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 c0 31 37 01 db 81 c7 ?? ?? ?? ?? 39 d7 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_RPY_2147900935_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.RPY!MTB"
        threat_id = "2147900935"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 10 40 21 fe 89 ff 39 d8 75 e2 c3 8d 14 0a 8b 12 47}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GMZ_2147901032_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GMZ!MTB"
        threat_id = "2147901032"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {01 f8 31 0b 43 39 d3}  //weight: 5, accuracy: High
        $x_5_2 = {29 fe 29 f6 8b 12 21 ff 01 fe}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_CCHS_2147903235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CCHS!MTB"
        threat_id = "2147903235"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 31 19 81 c0 31 ?? ?? ?? ?? 09 ff 81 ef ?? ?? ?? ?? 39 f1 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GNW_2147904164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GNW!MTB"
        threat_id = "2147904164"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {5f 31 0e 81 ef ?? ?? ?? ?? 01 fa 81 c6 ?? ?? ?? ?? 09 fa 81 c2 ?? ?? ?? ?? 39 c6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPK_2147905960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPK!MTB"
        threat_id = "2147905960"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 d8 85 40 00 59 [0-80] 81 e1 ff 00 00 00}  //weight: 4, accuracy: Low
        $x_4_2 = {68 d8 85 40 00 58 [0-80] 81 e2 ff 00 00 00}  //weight: 4, accuracy: Low
        $x_4_3 = {68 d8 85 40 00 5a [0-80] 81 e2 ff 00 00 00}  //weight: 4, accuracy: Low
        $x_4_4 = {ba d8 85 40 00 b8 [0-80] 81 e2 ff 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_CCIB_2147906108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.CCIB!MTB"
        threat_id = "2147906108"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {29 db 09 d2 e8 ?? ?? ?? ?? 31 38 4b 40 29 d2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPX_2147906747_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPX!MTB"
        threat_id = "2147906747"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {d8 85 40 00 [0-48] 31 [0-63] ff 00 00 00 [0-95] 81 ?? f4 01 00 00 75 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPL_2147910298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPL!MTB"
        threat_id = "2147910298"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {b8 d8 85 40 00 81 [0-80] 81 e0 ff 00 00 00}  //weight: 4, accuracy: Low
        $x_4_2 = {b8 d8 85 40 00 57 [0-80] 81 e0 ff 00 00 00}  //weight: 4, accuracy: Low
        $x_4_3 = {ba d8 85 40 00 83 [0-80] 81 e2 ff 00 00 00}  //weight: 4, accuracy: Low
        $x_4_4 = {68 d8 85 40 00 5f [0-80] 81 e7 ff 00 00 00}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_GPA_2147910300_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPA!MTB"
        threat_id = "2147910300"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 8b 5d 00 [0-48] 31 [0-63] ff 00 00 00 [0-95] 81 ?? f4 01 00 00 75 05}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPAB_2147911295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPAB!MTB"
        threat_id = "2147911295"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 8a 43 00 [0-48] 31 [0-63] ff 00 00 00 [0-95] 81 ?? f4 01 00 00 75 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPAC_2147911390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPAC!MTB"
        threat_id = "2147911390"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {c1 b3 43 00 [0-48] 31 [0-63] ff 00 00 00 [0-95] 81 ?? f4 01 00 00 75 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_AMAX_2147917214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.AMAX!MTB"
        threat_id = "2147917214"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1e b2 47 00 [0-15] 12 b4 47 00 [0-40] 81 ?? ff 00 00 00 [0-20] 31 [0-55] 81 ?? 34 b4 47 00 0f 8c ?? ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_KAV_2147917474_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.KAV!MTB"
        threat_id = "2147917474"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7c 9a 65 00 [0-20] 70 9c 65 00 [0-40] 81 ?? ff 00 00 00 [0-15] 31 [0-50] 81 ?? 92 9c 65 00 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPAD_2147919411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPAD!MTB"
        threat_id = "2147919411"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {14 8a 43 00 [0-48] 31 [0-96] ff 00 00 00 [0-95] 81 ?? f4 01 00 00 75 05}  //weight: 4, accuracy: Low
        $x_4_2 = {c1 b3 43 00 [0-48] 31 [0-96] ff 00 00 00 [0-95] 81 ?? f4 01 00 00 75 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_MKZ_2147929699_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.MKZ!MTB"
        threat_id = "2147929699"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f7 d1 be de 5a 6f a9 81 c1 01 00 00 00 f7 d6 f7 d6 31 3b 29 ce 41 81 c3 02 00 00 00 81 e9 01 00 00 00 be 40 3e df 8f 81 c1 8f 5d 9f aa 39 d3 0f 8c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPXA_2147930768_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPXA!MTB"
        threat_id = "2147930768"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {96 87 a7 00 [0-48] 8a 89 a7 00 [0-48] 81 ?? ff 00 00 00 [0-48] 31 [0-112] 0f}  //weight: 4, accuracy: Low
        $x_1_2 = "VirtualProtect" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_BAA_2147937897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BAA!MTB"
        threat_id = "2147937897"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {31 3a 29 c1 81 c2 04 00 00 00 01 c9 46 39 da 75}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPI_2147939820_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPI!MTB"
        threat_id = "2147939820"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 b3 43 00 [0-16] e8 [0-32] 31 [0-64] 75 [0-64] 81 ?? ff 00 00 00 [0-64] 81 ?? f4 01 00 00 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPJ_2147939821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPJ!MTB"
        threat_id = "2147939821"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {a2 ad 47 00 [0-8] 96 af 47 00 [0-48] 81 ?? ff 00 00 00 [0-32] 31 [0-48] 0f 8c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_GPAK_2147940823_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.GPAK!MTB"
        threat_id = "2147940823"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {68 e0 ea 40 00 [0-32] 31 [0-48] 81 ?? ff 00 00 00 [0-32] f4 01 00 00 75 05}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_BAB_2147956283_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BAB!MTB"
        threat_id = "2147956283"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {c1 ea 05 03 55 e0 33 c2 8b 4d fc 2b c8 89 4d fc 8b 55 f4 2b 55 dc 89 55 f4 eb ?? b8 04 00 00 00 6b c8 00 8b 55 08 8b 45 fc 89 04 0a b9 04 00 00 00 c1 e1 00 8b 55 08 8b 45 f8 89 04 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_PGCP_2147957050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.PGCP!MTB"
        threat_id = "2147957050"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a0 86 45 00 c3 [0-31] cc ?? 47 00 [0-31] e8 ?? 00 00 00 [0-26] 31 [0-15] 81 ?? 02 00 00 00 [0-15] 39 ?? 7c}  //weight: 5, accuracy: Low
        $x_5_2 = {a0 96 45 00 c3 [0-31] cc ?? 47 00 [0-31] e8 ?? 00 00 00 [0-26] 31 [0-15] 81 ?? 02 00 00 00 [0-15] 39 ?? 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_SPIP_2147958041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPIP!MTB"
        threat_id = "2147958041"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {81 c2 12 97 e5 c7 31 38 81 c1 df ff ba ad 81 c2 ed c7 ed c7 81 c0 02 00 00 00 81 ea cb 0b 38 3c 81 c1 01 00 00 00 81 e9 10 f3 a5 21 39 f0 7c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_SPIW_2147958042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.SPIW!MTB"
        threat_id = "2147958042"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = {43 31 17 81 c3 01 00 00 00 81 c7 02 00 00 00 81 c3 01 00 00 00 39 f7 7c}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_PGCO_2147958417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.PGCO!MTB"
        threat_id = "2147958417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a0 56 46 00 c3 [0-26] 08 4a 48 00 [0-26] e8 ?? 00 00 00 [0-26] 31 [0-26] 81 ?? 02 00 00 00 [0-15] 39 ?? 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_PGCO_2147958417_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.PGCO!MTB"
        threat_id = "2147958417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a0 56 46 00 c3 [0-15] 08 4a 48 00 [0-10] e8 ?? 00 00 00 [0-15] 31 [0-8] 81 ?? 02 00 00 00 [0-15] 39 ?? 7c}  //weight: 5, accuracy: Low
        $x_5_2 = {a0 96 45 00 c3 [0-26] cc 46 47 00 [0-26] e8 ?? 00 00 00 [0-31] 31 [0-26] 81 ?? 02 00 00 00 [0-26] 39 ?? 7c}  //weight: 5, accuracy: Low
        $x_5_3 = {a0 86 45 00 c3 [0-26] cc 35 47 00 [0-26] e8 ?? 00 00 00 [0-31] 31 [0-26] 81 ?? 02 00 00 00 [0-26] 39 ?? 7c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_Copak_BAD_2147958531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BAD!MTB"
        threat_id = "2147958531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8a 1a 09 c9 89 ce 88 1f 21 f1 81 ee 01 00 00 00 29 f1 81 c7 01 00 00 00 09 f1 89 ce 09 f6 81 c2 02 00 00 00 4e 09 f1 01 f1 39 c2 7e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_BAC_2147958550_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BAC!MTB"
        threat_id = "2147958550"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4e 8a 17 21 f0 88 11 89 f6 48 81 c6 ?? ?? ?? ?? 41 01 f6 46 81 c7 02 00 00 00 21 c0 01 c0 39 df 7e}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_BAE_2147958992_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BAE!MTB"
        threat_id = "2147958992"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {09 cf 09 cf 29 cf 31 13 81 ef ?? ?? ?? ?? 81 c1 ?? ?? ?? ?? 83 ec 04 c7 04 24 ?? ?? ?? ?? 8b 0c 24 83 c4 04 81 c3 02 00 00 00 41 39 f3 7c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Copak_BAF_2147959920_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Copak.BAF!MTB"
        threat_id = "2147959920"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Copak"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 c8 8b 3f 41 29 c1 29 c0 81 e7 ff 00 00 00 29 c9 42 01 c9 21 c0 b9 ?? ?? ?? ?? 81 fa f4 01 00 00 75}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

