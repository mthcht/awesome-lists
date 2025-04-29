rule Trojan_Win64_LummaC_AA_2147898573_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.AA!MTB"
        threat_id = "2147898573"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 8b 04 24 8b 54 24 18 48 8b 4c 24 08 4c 63 44 24 1c 42 8b 0c 81 4c 63 c1 42 33 14 80 48 63 c9 89 14 88 8b 44 24 1c 83 c0 01 89 44 24 1c e9 bf ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_CZ_2147926868_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.CZ!MTB"
        threat_id = "2147926868"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " Go build ID:" ascii //weight: 1
        $x_2_2 = "v4INt8xihDGvnrfjMDVXGxw9wrfxYyCjk0KbXjhR55s" ascii //weight: 2
        $x_2_3 = "RQqyEogx5J6wPdoxqL132b100j8KjcVHO1c0KLRoIhc" ascii //weight: 2
        $x_2_4 = "6EUwBLQ/Mcr1EYLE4Tn1VdW1A4ckqCQWZBw8Hr0kjpQ" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_YAN_2147929558_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.YAN!MTB"
        threat_id = "2147929558"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_11_1 = {59 58 44 30 24 0f 49 31 cc 48 ff c1 48 89 c8}  //weight: 11, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_AMCZ_2147930987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.AMCZ!MTB"
        threat_id = "2147930987"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 0f bf c2 c1 ea ?? 41 c1 f8 ?? 41 01 d0 44 89 c2 c1 e2 ?? 41 29 d0 44 01 c1 81 c1 ?? ?? ?? ?? 8d 51 ?? 66 83 f9 ?? 0f b6 d2 0f 42 d1 88 94 05 ?? ?? ?? ?? 48 ff c0 48 83 f8 ?? 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_GA_2147932798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.GA!MTB"
        threat_id = "2147932798"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 03 c8 8b d1 89 50 20 8b c5 99 f7 f9 8d a8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_NZ_2147933340_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.NZ!MTB"
        threat_id = "2147933340"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Go build ID: " ascii //weight: 1
        $x_2_2 = "aTy974I1vPDYPFzoFH4vtJONrK4oRDvjUxteUan7beE" ascii //weight: 2
        $x_2_3 = "DrRLnoQFxHWJ5lJUmrH7X2L0xeUu6SUS95Dc61eW2Yc" ascii //weight: 2
        $x_2_4 = "RQqyEogx5J6wPdoxqL132b100j8KjcVHO1c0KLRoIhc" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_YAP_2147934476_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.YAP!MTB"
        threat_id = "2147934476"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {43 02 04 37 0f b6 c0 41 8a 04 07 4c 8b 7d ?? 48 8b 4d ?? 4c 8b 75 ?? 42 32 04 31 42 88 04 31}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_CCIS_2147936486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.CCIS!MTB"
        threat_id = "2147936486"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 21 da 45 09 f9 44 09 d6 41 31 f1 44 88 4c 24 0b 44 8a 44 24 0b 48 8b 4c 24 10 48 63 54 24 0c 44 88 04 11 44 8b 54 24 0c}  //weight: 1, accuracy: High
        $x_1_2 = {44 21 de 09 f3 88 5c 24 2b 44 8a 44 24 2b 48 8b 4c 24 30 48 63 54 24 2c 44 88 04 11 44 8b 4c 24 2c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win64_LummaC_CCJU_2147936885_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.CCJU!MTB"
        threat_id = "2147936885"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stop reversing the binary" ascii //weight: 1
        $x_1_2 = "Reconsider your life choices" ascii //weight: 1
        $x_1_3 = "And go touch some grass" ascii //weight: 1
        $x_5_4 = "\\%SexBot%\\modules\\stubmain" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_ALA_2147937736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.ALA!MTB"
        threat_id = "2147937736"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 03 c8 0f b6 01 43 88 04 08 44 88 11 43 0f b6 0c 08 49 03 ca 0f b6 c1 0f b6 8c 04 00 01 00 00 30 0f 48 ff c7 49 83 eb 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_GTK_2147937737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.GTK!MTB"
        threat_id = "2147937737"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 20 d0 41 88 c2 41 80 f2 ?? 41 80 e2 ?? 20 d0 45 08 c1 41 08 c2 45 30 d1 88 c8 44 20 c8 44 30 c9 08 c8 a8 01 41 be ?? ?? ?? ?? 41 bf ?? ?? ?? ?? 45 0f 45 fe 44 89 7d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_PGLC_2147937927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.PGLC!MTB"
        threat_id = "2147937927"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {34 01 24 00 41 80 e4 01 45 08 ee 44 08 e0 41 30 c6 41 80 f6 ff 40 88 f8 34 00 41 88 fc 41 80 f4 01 41 08 c6 41 80 cc 01 41 80 f6 ff 45 20 e6 40 88 f8}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_GTX_2147938066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.GTX!MTB"
        threat_id = "2147938066"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {41 88 d1 41 80 e1 ?? 44 20 ee 88 5d b4 80 e3 ?? 45 20 ee 41 08 f1 44 08 f3 41 30 d9 8a 5d b4 08 da}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_GTY_2147938067_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.GTY!MTB"
        threat_id = "2147938067"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {45 08 e6 45 08 fd 45 30 ee 45 88 df 41 80 f7 ?? 41 88 dc 41 80 f4 ?? 41 88 fd 41 80 f5 ?? 45 88 fa 41 80 e2 ?? 45 20 eb 44 88 a5}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_PGLD_2147938069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.PGLD!MTB"
        threat_id = "2147938069"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {40 88 f8 34 01 24 00 41 80 e4 ?? 45 08 ee 44 08 e0 41 30 c6 41 80 f6 ff 40 88 f8 34 00 41 88 fc 41 80 f4 ?? 41 08 c6 41 80 cc ?? 41 80 f6 ff 45 20 e6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_PGLF_2147938070_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.PGLF!MTB"
        threat_id = "2147938070"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {34 01 24 00 41 80 e4 ?? 45 08 ef 44 08 e0 41 30 c7 41 80 f7 ?? 88 d8 44 30 f8 20 d8 41 88 ff 41 20 c7 40 30 c7 41 08 ff 40 88 f0 34 ff 24 01 44 88 f7 40 80 f7 ?? 41 88 f4 41 20 fc 45 88 f5}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_PGAL_2147938071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.PGAL!MTB"
        threat_id = "2147938071"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {29 c6 44 0f af ce 41 83 e1 01 41 83 f9 00 0f 94 c3 80 e3 01 88 5d f6 41 83 fa 0a 0f 9c c3 80 e3 01 88 5d f7}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_GF_2147938154_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.GF!MTB"
        threat_id = "2147938154"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {88 c1 40 30 f1 20 c1 88 d0 20 c8 30 ca 08 d0 88 c1 80 f1 ff 80 e1 01 8a 55 e2}  //weight: 3, accuracy: High
        $x_2_2 = {20 c8 41 30 cb 44 08 d8 44 88 c1 80 f1 ff 88 c2 20 ca}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_EASW_2147939217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.EASW!MTB"
        threat_id = "2147939217"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {48 09 eb 48 f7 d0 48 31 c3 48 f7 d3 48 21 c3 48 89 5c 24 58 b8 3a ad fd d5 3d 3a 98 52 e6}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_PGLA_2147939227_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.PGLA!MTB"
        threat_id = "2147939227"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0f 9c c2 89 d3 30 cb 08 ca 80 f2 01 08 da 41 89 d0 41 30 d8 84 d2 b9 ?? ?? ?? ?? 41 0f 45 cc 84 db 41 0f 44 cc 48 89 84 24}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_GTM_2147939252_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.GTM!MTB"
        threat_id = "2147939252"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 30 c0 41 89 d8 41 20 c0 30 d8 44 08 c0}  //weight: 5, accuracy: High
        $x_5_2 = {0f 45 c6 84 db ba ?? ?? ?? ?? 0f 45 c2 48 89 7d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_PGT_2147939437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.PGT!MTB"
        threat_id = "2147939437"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 89 c3 41 80 e3 6e 80 e2 91 44 08 da 08 d8 80 e3 6e 80 e1 91 08 d9 30 d1 f6 d0 08 c8 48 8b 8d 30 02 00 00 41 88 44 0a 01 48 8b 85 ?? ?? ?? ?? 48 8b 85 30 02 00 00 48 8b 85 30 02 00 00 bb 16 ca 0c 55 81 fb 86 2f 0b d3 0f 8f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_GMT_2147940011_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.GMT!MTB"
        threat_id = "2147940011"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {44 30 c1 44 08 c2 80 f2 ?? 08 ca 41 89 d0 41 30 d8 84 d2 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? 0f 45 ca 84 db 0f 44 ca 48 89 44 24}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_LummaC_MGB_2147940256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/LummaC.MGB!MTB"
        threat_id = "2147940256"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "LummaC"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {f6 d0 44 89 d9 20 c1 44 30 d8 08 c8 89 c1 f6 d1 80 e1 d8 24 27 08 c8 89 c1 80 f1 27 34 c0 24 c1 89 cf 40 80 e7 3e 40 08 c7 41 89 f8 41 80 f0 3e 89 f0 34 9a 41 89 c3 41 20 f3}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

