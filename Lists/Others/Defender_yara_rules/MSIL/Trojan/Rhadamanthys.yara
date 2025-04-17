rule Trojan_MSIL_Rhadamanthys_ARH_2147841949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.ARH!MTB"
        threat_id = "2147841949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 1b 2d 03 26 2b 66 0a 2b fb 00 72 01 00 00 70 28 ?? ?? ?? 06 73 02 00 00 0a 16 2c 03 26 2b 03 0b 2b 00 73 03 00 00 0a 1b 2d 03 26 2b 03 0c 2b 00 07 16 73 04 00 00 0a 73 05 00 00 0a 0d 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_ARH_2147841949_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.ARH!MTB"
        threat_id = "2147841949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 06 6f ?? 00 00 0a 0d 00 07 16 fe 01 13 07 11 07 ?? ?? ?? ?? ?? ?? 16 0b 06 13 08 11 08 1f 20 2e 14 11 08 1f 2e 2e 77}  //weight: 1, accuracy: Low
        $x_2_2 = {08 09 1f 41 59 1f 5b 58 d2 28 ?? 00 00 06 00 00 2b 38 09 1f 61 32 07 09 1f 7a fe 02 2b 01 17 00 13 07 11 07 2d 18 00 7e ?? 00 00 04 08 09 1f 61 59 1f 75 58 d2}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_ARH_2147841949_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.ARH!MTB"
        threat_id = "2147841949"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 11 10 1f 0c 58 28 ?? 00 00 06 13 13 02 11 10 1f 10 58 28 ?? 00 00 06 13 14 02 11 10 1f 14 58 28 ?? 00 00 06 13 15 11 14 16 31 3e 11 14 8d 14 00 00 01 13 16 02 11 15 11 16 16 11 16 8e 69 28 ?? 00 00 0a 7e 07 00 00 04 12 06 7b 0b 00 00 04 11 0f 11 13 58 11 16 11 16 8e 69 12 04}  //weight: 2, accuracy: Low
        $x_5_2 = "147.45.44.42" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_NEAA_2147844545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.NEAA!MTB"
        threat_id = "2147844545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 00 06 13 00 38 00 00 00 00 28 02 00 00 0a 11 00 6f 03 00 00 0a 28 04 00 00 0a 28 05 00 00 06 13 01 38 00 00 00 00 dd 10 00 00 00 26 38 00 00 00 00 dd ?? ?? ?? ?? 38 00 00 00 00 11 01 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_ARY_2147894231_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.ARY!MTB"
        threat_id = "2147894231"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 0b 16 0c 2b 15 03 08 03 08 9a 04 72 ?? 06 00 70 6f ?? 00 00 0a a2 08 17 d6 0c 08 07 31 e7}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_RS_2147899245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.RS!MTB"
        threat_id = "2147899245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 28 12 00 00 06 0a 28 03 00 00 0a 06 6f 04 00 00 0a 28 05 00 00 0a 28 01 00 00 2b 28 02 00 00 2b 0b de 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_MBZU_2147906133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.MBZU!MTB"
        threat_id = "2147906133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 61 73 69 73 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 43 6f 72 72 65 63 74 00 4d 53 47 5f 4e 45 54 00 4f 62 6a 65 63 74 00 50 72 6f 67 72 61 6d 00 41 6e 67 65 6c 6f 00 44 67 61 73 79 75 64 67 75 79 67 69 75 78 48 49 41 00 4d 75 6c 74 69 63 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_ARM_2147927636_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.ARM!MTB"
        threat_id = "2147927636"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6c 03 6c 5b 28 ?? 00 00 06 69 0a 06 8d ?? 00 00 01 0b 16 0c 2b 2b 00 08 03 5a 0d 7e ?? 00 00 04 03 02 6f ?? 00 00 0a 09 59 28 ?? 00 00 06 13 04 07 08 02 09 11 04 6f ?? 00 00 0a a2 00 08 17 58 0c 08 06 fe 04 13 06 11 06}  //weight: 2, accuracy: Low
        $x_1_2 = "newcrypternoprocess.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_BK_2147932339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.BK!MTB"
        threat_id = "2147932339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {13 06 11 06 07 16 07 8e 69 6f ?? 00 00 0a 73 ?? 00 00 0a 16 73 ?? 00 00 0a 13 07 11 07 14 fe 01 13 10 11 10 2d 4c}  //weight: 3, accuracy: Low
        $x_1_2 = "_k_k Ll V.mTN b p_hm5_M G1W5.L:" wide //weight: 1
        $x_1_3 = "9qLYTBA0MX=rN&" wide //weight: 1
        $x_2_4 = "P.4.g_j_h M_e.4uN T G h.wJG_C.K v.7 R" wide //weight: 2
        $x_1_5 = "Z F u.i-wSpu M u_DK d_ai_YU I Z4.2.n.7" wide //weight: 1
        $x_1_6 = "vvi q_JP7.OAUG_V_yJw z.I y+_i.b.a_b.DQ_xx" wide //weight: 1
        $x_1_7 = "g.L.Y QA_WwW_M.e k P_b.p.2_M]_t.j.S.x*.ce" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Rhadamanthys_BN_2147934826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.BN!MTB"
        threat_id = "2147934826"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 00 06 1b 3a ?? 00 00 00 26 20 00 00 00 00 7e}  //weight: 2, accuracy: Low
        $x_2_2 = {ff ff 26 20 00 00 00 00 38 ?? ff ff ff dd ?? 00 00 00 13}  //weight: 2, accuracy: Low
        $x_1_3 = "Lrelfunmmxbuqifzq" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_SPS_2147935979_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.SPS!MTB"
        threat_id = "2147935979"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UEsDBBQAAAAIAJqDY1rJvu+i8SkKAAAEDAAHAAAAZzJtLmRsbOxafXgTVbo/0w6Q0sAECFABoUh3lUX5UK4rV1xblsHqM" ascii //weight: 1
        $x_1_2 = "rdha.exe" ascii //weight: 1
        $x_1_3 = "ExtractedZip_1cf60734\\package" ascii //weight: 1
        $x_1_4 = "g2m.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_UDP_2147937925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.UDP!MTB"
        threat_id = "2147937925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 0f 11 09 16 73 3e 00 00 0a 13 06 20 00 00 00 00 7e 7a 02 00 04 7b 7b 02 00 04 3a 0f 00 00 00 26 20 00 00 00 00 38 04 00 00 00 fe 0c 0a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Rhadamanthys_RK_2147939368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Rhadamanthys.RK!MTB"
        threat_id = "2147939368"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Rhadamanthys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {07 1f 10 8d 1d 00 00 01 25 d0 55 02 00 04 28 6f 00 00 0a 6f d6 00 00 0a 06 07 6f d7 00 00 0a 17 73 3b 00 00 0a 25 02 16 02 8e 69 6f d8 00 00 0a 6f d9 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

