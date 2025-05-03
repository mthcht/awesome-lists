rule Trojan_MSIL_SnakeKeyLogger_AB_2147828454_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AB!MTB"
        threat_id = "2147828454"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 02 02 8e 69 17 59 91 1f 70 61 0b 02 8e 69 17 58 8d ?? ?? ?? 01 0c 16}  //weight: 1, accuracy: Low
        $x_1_2 = {02 11 04 91 07 61 06 09 91 61 13 05 08 11 04 11 05 d2 9c 09 03 6f ?? ?? ?? 0a [0-3] 58 [0-3] 59 fe 01 13 06 11 06 2c 04 16 0d 2b ?? 09 [0-3] 58 [0-4] 0d 00 11 04 17 58 13 04 11 04 02 8e 69 17 59 [0-8] fe 02 16 fe 01 13 07 11 07 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_PD_2147832583_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.PD!MTB"
        threat_id = "2147832583"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 16 5d 13 07 11 06 17 58 13 08 07 11 08 07 8e 69 5d 91 13 09 08 11 07 91 13 0a 07 11 06 91 11 0a 61 13 0b 20 e4 8e fb 0e 13 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDB_2147837816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDB!MTB"
        threat_id = "2147837816"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1438f3a5-e4a1-475e-a7e0-e821f77343de" ascii //weight: 1
        $x_1_2 = "EnerGov" ascii //weight: 1
        $x_1_3 = "String1" ascii //weight: 1
        $x_1_4 = "ClaimsId" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDC_2147838062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDC!MTB"
        threat_id = "2147838062"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d05caeea-19be-4a4a-8705-395b52d7d446" ascii //weight: 1
        $x_1_2 = "kernel32" ascii //weight: 1
        $x_1_3 = "GetProcAddress" ascii //weight: 1
        $x_1_4 = "LoadLibrary" ascii //weight: 1
        $x_1_5 = "Ebook_Ordering" ascii //weight: 1
        $x_1_6 = "OKMLPOKM" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDA_2147842263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDA!MTB"
        threat_id = "2147842263"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 09 07 09 07 8e 69 5d 91 03 09 91 61 d2 9c 09 17 58 0d 09 03 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AC_2147843622_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AC!MTB"
        threat_id = "2147843622"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 05 00 00 06 28 05 00 00 06 28 05 00 00 06 28 05 00 00 06 28 05 00 00 06 72 49 00 00 70 16 28 0b 00 00 06 80 05 00 00 04 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDG_2147845147_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDG!MTB"
        threat_id = "2147845147"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Timedix Serenty" ascii //weight: 1
        $x_1_2 = "ErbnKhOBiWTSRKE.ErbnKhOBiWTSRKE" wide //weight: 1
        $x_1_3 = "hWQHlSOxHQKaNDv" wide //weight: 1
        $x_1_4 = "aselrias38490a32" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDH_2147846888_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDH!MTB"
        threat_id = "2147846888"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 09 18 6f 0f 01 00 0a 1f 10 28 10 01 00 0a 28 11 01 00 0a 16 91 13 05 08 11 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDI_2147846890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDI!MTB"
        threat_id = "2147846890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "46e5c5e6-7e47-4c01-90ce-35585ce40627" ascii //weight: 1
        $x_1_2 = "VBGV76" ascii //weight: 1
        $x_1_3 = "c3c54cace5e9c2c5b1ea0f85e09e3401e" ascii //weight: 1
        $x_1_4 = "VkJHVjc2JA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDJ_2147848265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDJ!MTB"
        threat_id = "2147848265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 7e 08 00 00 04 6f 25 00 00 0a 02 16 04 8e 69 6f 26 00 00 0a 0a 06 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDJ_2147848265_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDJ!MTB"
        threat_id = "2147848265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7d 8a 01 00 04 06 06 7b 8a 01 00 04 28 01 00 00 2b 28 02 00 00 2b 73 b6 00 00 0a 7d 8a 01 00 04 16 06 7b 8a 01 00 04 6f b7 00 00 0a 28 b8 00 00 0a 7e 8c 01 00 04 25}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDJ_2147848265_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDJ!MTB"
        threat_id = "2147848265"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "9495b04a-4307-4bad-a783-f9417235bb38" ascii //weight: 1
        $x_1_2 = "WindowsFormKlass" ascii //weight: 1
        $x_1_3 = "SpaceTeam" ascii //weight: 1
        $x_1_4 = "AxvhMfnyTrBArEBQAyLhAhZBOw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDK_2147849607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDK!MTB"
        threat_id = "2147849607"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "351ce5b2-b474-4ba9-a4c5-13ec25b3d8b8" ascii //weight: 1
        $x_1_2 = "YFGGCVyufgtwfyuTGFWTVFAUYVF" ascii //weight: 1
        $x_1_3 = "Xudzxq" ascii //weight: 1
        $x_1_4 = "VisitorObjectResolver" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDM_2147849608_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDM!MTB"
        threat_id = "2147849608"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HB 766" ascii //weight: 1
        $x_1_2 = "aR3nbf8dQp2feLmk31" ascii //weight: 1
        $x_1_3 = "lSfgApatkdxsVcGcrktoFd" ascii //weight: 1
        $x_1_4 = "b59d10a0-3f49-4348-bfde-272c92a212f6" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDQ_2147850787_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDQ!MTB"
        threat_id = "2147850787"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "8a020a5b-d8aa-4c9f-a1ee-73fb6678cdbe" ascii //weight: 1
        $x_1_2 = "CaesarShift" ascii //weight: 1
        $x_1_3 = "FIxzpKu" ascii //weight: 1
        $x_1_4 = "TTTTTTTTTTTTTTTTTTTTTTTTT_TK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDR_2147851445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDR!MTB"
        threat_id = "2147851445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 18 00 00 0a 6f 19 00 00 0a 28 26 00 00 06 6f 1a 00 00 0a 6f 1b 00 00 0a 13 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDS_2147852214_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDS!MTB"
        threat_id = "2147852214"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 55 03 00 04 6f c5 00 00 0a 05 03 02 8e 69 6f c6 00 00 0a 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDT_2147852565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDT!MTB"
        threat_id = "2147852565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 50 01 00 0a 6f 51 01 00 0a 28 ?? ?? ?? ?? 6f 52 01 00 0a 6f 53 01 00 0a 13 06 20}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDU_2147852774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDU!MTB"
        threat_id = "2147852774"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 87 00 00 0a 6f 89 00 00 0a 06 06 6f 8a 00 00 0a 06 6f 8b 00 00 0a 6f 8c 00 00 0a 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDV_2147890304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDV!MTB"
        threat_id = "2147890304"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 05 6f 5f 01 00 0a 13 06 73 3d 00 00 0a 0a 03 75 13 00 00 1b 73 60 01 00 0a 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDW_2147890525_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDW!MTB"
        threat_id = "2147890525"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 0a 00 00 0a 6f 0b 00 00 0a 0b 73 0c 00 00 0a 0c 02 28 02 00 00 06 75 03 00 00 1b 73 0d 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDX_2147890526_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDX!MTB"
        threat_id = "2147890526"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 02 11 00 11 08 6f 07 00 00 0a 13 0c 20}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDY_2147891332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDY!MTB"
        threat_id = "2147891332"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 11 00 00 0a 6f 12 00 00 0a 0b 73 13 00 00 0a 0c 02 28 06 00 00 06 75 01 00 00 1b 73 14 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDZ_2147891401_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDZ!MTB"
        threat_id = "2147891401"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 2f 00 00 0a 02 6f 30 00 00 0a 0a 06 6f 31 00 00 0a 0b 07 16 9a 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAB_2147893863_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAB!MTB"
        threat_id = "2147893863"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 9e 00 00 0a 59 d2 9c 07 17 58 0b 07 02 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAA_2147893866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAA!MTB"
        threat_id = "2147893866"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 31 00 00 0a 05 03 02 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAC_2147893925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAC!MTB"
        threat_id = "2147893925"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {05 03 02 8e 69 6f 34 00 00 0a 0a 06 28 35 00 00 0a 00 06 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAD_2147893937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAD!MTB"
        threat_id = "2147893937"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 28 bf 00 00 0a 02 6f c0 00 00 0a 6f c1 00 00 0a 1f 23 9a 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAE_2147894400_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAE!MTB"
        threat_id = "2147894400"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 1f 00 00 0a 0c 02 7b 13 00 00 04 6f 20 00 00 0a 16 6a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAF_2147894624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAF!MTB"
        threat_id = "2147894624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 02 7b 0e 00 00 04 6f 23 00 00 0a 02 7b 0e 00 00 04 6f 24 00 00 0a 13 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAG_2147895100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAG!MTB"
        threat_id = "2147895100"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 02 7b ?? ?? ?? ?? 6f 26 00 00 0a 02 7b ?? ?? ?? ?? 6f 27 00 00 0a 13 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAH_2147895206_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAH!MTB"
        threat_id = "2147895206"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ERPReportUtils" ascii //weight: 1
        $x_1_2 = "Example" ascii //weight: 1
        $x_1_3 = "Bolkvadze" ascii //weight: 1
        $x_1_4 = "FactSales" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAI_2147895577_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAI!MTB"
        threat_id = "2147895577"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 0b 91 61 13 0d 20 00 01 00 00 13 06 11 0d 07 11 0c 91 59 11 06 58 11 06 5d 13 0e 07 11 05 11 0e}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDO_2147895966_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDO!MTB"
        threat_id = "2147895966"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 22 01 00 06 28 4f 00 00 0a 6f 50 00 00 0a 6f 51 00 00 0a 6f 52 00 00 0a 6f 53 00 00 0a 13 01}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDL_2147896727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDL!MTB"
        threat_id = "2147896727"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DACls" ascii //weight: 1
        $x_1_2 = "qJJQNyhOJ5GTtI2xkTW" ascii //weight: 1
        $x_1_3 = "BgdTuRCrXS" ascii //weight: 1
        $x_1_4 = "NqSXc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAJ_2147896927_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAJ!MTB"
        threat_id = "2147896927"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 04 6f 3c 00 00 0a 5d 6f 3d 00 00 0a 61 d2 9c 11 05 17 58}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAK_2147899133_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAK!MTB"
        threat_id = "2147899133"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 04 03 8e 69 6f ?? ?? ?? ?? 0a 06 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAL_2147899478_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAL!MTB"
        threat_id = "2147899478"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 05 03 8e 69 6f ?? ?? ?? ?? 0a 06 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAN_2147899762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAN!MTB"
        threat_id = "2147899762"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 0e 04 04 8e 69 6f ?? ?? ?? ?? 0a 06 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAO_2147900413_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAO!MTB"
        threat_id = "2147900413"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {04 8e 69 6f 39 00 00 0a 0a 06 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAP_2147900836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAP!MTB"
        threat_id = "2147900836"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0d 61 13 0f 11 0f 11 0e 59 13 10 07 11 0a 11 10 11 08 5d d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_MVT_2147900847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.MVT!MTB"
        threat_id = "2147900847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {05 05 05 05 05 0e 06 28 08 00 00 06 0a 2b 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAQ_2147901954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAQ!MTB"
        threat_id = "2147901954"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Andrewsy Lib" ascii //weight: 1
        $x_1_2 = "WordProcessorChamberlin" ascii //weight: 1
        $x_1_3 = "ChildEditor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAR_2147902211_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAR!MTB"
        threat_id = "2147902211"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5d 91 08 58 08 5d 59 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAS_2147902875_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAS!MTB"
        threat_id = "2147902875"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 8e 69 6f b0 00 00 0a 13 0a 11 0a 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAT_2147903384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAT!MTB"
        threat_id = "2147903384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5d 91 61 07 09 17 58 08 5d 91 59}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AX_2147905289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AX!MTB"
        threat_id = "2147905289"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 0f 11 0e 11 0f 61 11 0d 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 10 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAU_2147906237_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAU!MTB"
        threat_id = "2147906237"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 11 05 1f 16 5d 91 13 08 07 11 05 91 11 08 61 13 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAV_2147909395_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAV!MTB"
        threat_id = "2147909395"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 09 91 11 0c 61 07 11 0d 91 59 13 0e 11 0e 20 00 01 00 00 58 13 0f 07 11 09 11 0f 20 ff 00 00 00 5f d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAW_2147911750_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAW!MTB"
        threat_id = "2147911750"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 59 13 04 06 09 28 03 00 00 2b 11 04 28 04 00 00 2b 28 05 00 00 2b 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAY_2147912245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAY!MTB"
        threat_id = "2147912245"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 04 91 11 05 61 13 06 07 11 04 17 58 07 8e 69 5d 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMMJ_2147912393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMMJ!MTB"
        threat_id = "2147912393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 08 91 07 08 07 8e 69 5d 91 61 d2 9c 00 08 17 58 0c 08 7e ?? 00 00 04 8e 69 fe 04 0d 09 2d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDAZ_2147912655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDAZ!MTB"
        threat_id = "2147912655"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 7e 88 01 00 04 6f 4b 00 00 0a 06 7e 89 01 00 04 6f 4c 00 00 0a 06 06}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBA_2147912874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBA!MTB"
        threat_id = "2147912874"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 2e 00 00 0a 6f 2f 00 00 0a 02 16 02 8e 69 6f 30 00 00 0a 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBA_2147912874_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBA!MTB"
        threat_id = "2147912874"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f c0 00 00 0a 28 c1 00 00 0a 6f c2 00 00 0a 0b 07 6f c3 00 00 0a 16 9a 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBB_2147914451_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBB!MTB"
        threat_id = "2147914451"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AukcionDBDataSet" ascii //weight: 1
        $x_1_2 = "DBidontwantgotothearmy" ascii //weight: 1
        $x_1_3 = "FormAddAukcion" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBC_2147914535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBC!MTB"
        threat_id = "2147914535"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Capture Recovery Tool" ascii //weight: 2
        $x_1_2 = "TechSmith Corporation" ascii //weight: 1
        $x_1_3 = "Camtasia Studio" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBD_2147915087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBD!MTB"
        threat_id = "2147915087"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Camtasia Studio" ascii //weight: 1
        $x_1_2 = "TechSmith Corporation" ascii //weight: 1
        $x_2_3 = "SearchCustomer" ascii //weight: 2
        $x_2_4 = "PostCustomer" ascii //weight: 2
        $x_2_5 = "ManageCustomer" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBE_2147915530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBE!MTB"
        threat_id = "2147915530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 6f 4c 00 00 0a 03 16 03 8e 69 6f 4d 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMAN_2147915942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMAN!MTB"
        threat_id = "2147915942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 91 13 [0-20] 61 [0-50] 59 20 00 01 00 00 58 20 ff 00 00 00 5f d2 9c 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBF_2147915984_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBF!MTB"
        threat_id = "2147915984"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 6f 23 00 00 0a 0c 03 73 24 00 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBG_2147916098_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBG!MTB"
        threat_id = "2147916098"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {91 11 07 61 13 08 11 06 17 58 08 5d 08 58 08 5d 13 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBH_2147916377_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBH!MTB"
        threat_id = "2147916377"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 02 00 00 0a 72 01 00 00 70 28 03 00 00 0a 6f 04 00 00 0a 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBI_2147916471_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBI!MTB"
        threat_id = "2147916471"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 5d 08 58 08 5d 13 06 07 11 06 08 5d 08 58 08 5d 91}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBJ_2147916726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBJ!MTB"
        threat_id = "2147916726"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5f 95 d2 13 12 11 10 11 12 61 13 13}  //weight: 2, accuracy: High
        $x_2_2 = {11 07 11 0f d4 11 13 20 ff 00 00 00 5f d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBK_2147916821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBK!MTB"
        threat_id = "2147916821"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 28 03 00 00 06 13 04 09 11 04 16 11 04 8e 69 6f 1f 00 00 0a 08 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBL_2147916953_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBL!MTB"
        threat_id = "2147916953"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {16 11 04 28 01 00 00 2b 8e 69 6f 08 00 00 0a 08 6f 09 00 00 0a 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBM_2147917167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBM!MTB"
        threat_id = "2147917167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 03 17 8d 06 00 00 01 25 16 09 20 b9 87 02 00 d6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBN_2147917302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBN!MTB"
        threat_id = "2147917302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 26 00 00 0a 0b 73 27 00 00 0a 0c 08 07 17 73 28 00 00 0a 0d 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBO_2147917707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBO!MTB"
        threat_id = "2147917707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 18 6f 15 00 00 0a 1f 10 28 16 00 00 0a 6f 17 00 00 0a 08 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBP_2147917708_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBP!MTB"
        threat_id = "2147917708"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 18 6f 17 00 00 0a 1f 10 28 18 00 00 0a 6f 19 00 00 0a 08 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBQ_2147917711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBQ!MTB"
        threat_id = "2147917711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 5f 01 00 0a 6f 60 01 00 0a 0b 73 61 01 00 0a 0c 16}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBR_2147918006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBR!MTB"
        threat_id = "2147918006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 08 18 6f 09 01 00 0a 1f 10 28 02 02 00 0a 6f 03 02 00 0a 08 18}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMAB_2147918531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMAB!MTB"
        threat_id = "2147918531"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {08 5d 08 58 13 [0-9] 5d 13 [0-20] 61 [0-5] 59 20 00 02 00 00 58 13 [0-10] 20 00 01 00 00 5d 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBS_2147918541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBS!MTB"
        threat_id = "2147918541"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 6a 00 00 2b 8e 69 6f 54 04 00 0a 08 6f 55 04 00 0a 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBT_2147918850_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBT!MTB"
        threat_id = "2147918850"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 10 17 58 08 5d 91 13 12 07 11 10 91 11 11 61 11 12 59 20 00 02 00 00 58 13 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_WFB_2147919301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.WFB!MTB"
        threat_id = "2147919301"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 05 01 00 06 26 09 17 58 0d 09 1a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMAH_2147919913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMAH!MTB"
        threat_id = "2147919913"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 d2 13 [0-15] 20 ff 00 00 00 5f 95 d2 [0-15] 61 [0-15] 20 ff 00 00 00 5f [0-20] 17 6a 58 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBU_2147920359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBU!MTB"
        threat_id = "2147920359"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 73 20 05 00 0a 0c 08 11 04 17 73 24 05 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBV_2147920779_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBV!MTB"
        threat_id = "2147920779"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 11 13 95 d2 13 14 09 11 12 07 11 12 91 11 14 61 d2 9c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_PN_2147920783_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.PN!MTB"
        threat_id = "2147920783"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {16 2d 0b 2b 0b 72 15 00 00 70 2b 07 2b 0c de 1a 07 2b f2 6f 17 00 00 0a 2b f2 0a 2b f1}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBW_2147921742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBW!MTB"
        threat_id = "2147921742"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 07 06 6f 30 00 00 0a 17 73 31 00 00 0a 0c 08 02 16 02 8e 69}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBX_2147921743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBX!MTB"
        threat_id = "2147921743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 0f 01 28 68 00 00 0a 6f 69 00 00 0a 00 02 0f 01 28 6a 00 00 0a 6f 69 00 00 0a 00 02 0f 01 28 6b 00 00 0a 6f 69 00 00 0a 00 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDBZ_2147921745_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDBZ!MTB"
        threat_id = "2147921745"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0b 07 09 11 04 6f 7b 00 00 0a 13 05 73 7c 00 00 0a 0a 06 11 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMF_2147922615_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMF!MTB"
        threat_id = "2147922615"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {00 02 06 07 6f ?? 00 00 0a 0c 03 6f ?? 00 00 0a 19 58 04 fe 02 16 fe 01 0d}  //weight: 3, accuracy: Low
        $x_2_2 = {02 0f 01 28 ?? 00 00 0a 6f ?? 00 00 0a 00 02 0f 01 28 ?? 00 00 0a 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_KAD_2147922624_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.KAD!MTB"
        threat_id = "2147922624"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 11 05 16 61 d2 6f ?? 00 00 0a 00 03 11 06 16 61 d2 6f ?? 00 00 0a 00 03 11 07 16 61 d2 6f ?? 00 00 0a 00 2b 15 03 6f ?? 00 00 0a 19 58 04 31 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCA_2147922914_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCA!MTB"
        threat_id = "2147922914"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0d 07 09 28 04 00 00 06 00 1d 28 13 00 00 0a 08 28 12 00 00 0a 13 04 09}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCB_2147923116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCB!MTB"
        threat_id = "2147923116"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "9d129655-6ca3-4900-a2f2-a3bb79e491cc" ascii //weight: 2
        $x_1_2 = "VMware Workstation" ascii //weight: 1
        $x_1_3 = "Player" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCC_2147923218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCC!MTB"
        threat_id = "2147923218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 09 03 09 91 05 09 07 5d 91 61 d2 9c 00 09 17 58 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMQ_2147923743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMQ!MTB"
        threat_id = "2147923743"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {95 58 20 ff 00 00 00 5f 13 [0-50] 95 58 20 ff 00 00 00 5f 13 [0-30] 61 13 [0-15] d2 9c [0-10] 17 58 13 [0-18] 8e 69 6a 32}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCD_2147924047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCD!MTB"
        threat_id = "2147924047"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 06 07 6f 11 00 00 0a 13 04 73 12 00 00 0a 13 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCE_2147924540_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCE!MTB"
        threat_id = "2147924540"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 0c 72 b1 00 00 70 28 1b 00 00 06 72 e3 00 00 70 28 1b 00 00 06 28 1c 00 00 06 13 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCF_2147924565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCF!MTB"
        threat_id = "2147924565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 08 72 af 00 00 70 28 1d 00 00 06 72 e1 00 00 70 28 13 00 00 0a 28 1e 00 00 06 13 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCG_2147924763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCG!MTB"
        threat_id = "2147924763"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 08 11 06 74 04 00 00 1b 73 bd 00 00 0a 16 17 73 be 00 00 0a 13 09 1d 13 14 11 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMX_2147925006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMX!MTB"
        threat_id = "2147925006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? ?? 00 0a 59 0d 03 08 09 28 ?? 00 00 06 00 03 08 09 28 ?? 00 00 06 00 03 6f ?? ?? 00 0a 04 fe 04 16 fe 01 13}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMX_2147925006_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMX!MTB"
        threat_id = "2147925006"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 08 08 6f ?? 00 00 0a 08 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 73 ?? 00 00 0a 13 04 11 04 09 17 73 ?? 00 00 0a 13 05 11 05 06 16 06 8e 69 6f ?? 00 00 0a 11 04 6f ?? 00 00 0a 0b de 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCH_2147925320_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCH!MTB"
        threat_id = "2147925320"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 07 1e 63 20 ff 00 00 00 5f d2 6f ab 00 00 0a 00 02 07 20 ff 00 00 00 5f d2}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCI_2147925667_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCI!MTB"
        threat_id = "2147925667"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 14 00 00 0a 72 a1 00 00 70 73 15 00 00 0a 28 16 00 00 0a 6f 17 00 00 0a 13 13}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCJ_2147925846_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCJ!MTB"
        threat_id = "2147925846"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 06 11 05 17 73 0a 00 00 0a 13 07}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCK_2147927069_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCK!MTB"
        threat_id = "2147927069"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 6f 67 01 00 0a 06 16 06 8e 69 6f 68 01 00 0a 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_RDCL_2147927123_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.RDCL!MTB"
        threat_id = "2147927123"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 07 8e 69 5d 91 61 d2 9c 00 11 04 17 58 13 04 11 04}  //weight: 2, accuracy: High
        $x_3_2 = {8e 69 5d 91 61 d2 9c 00 11 06 17 58 13 06 11 06}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMCW_2147929516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMCW!MTB"
        threat_id = "2147929516"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {53 00 6e 00 61 00 6b 00 65 00 20 00 4b 00 65 00 79 00 6c 00 6f 00 67 00 67 00 65 00 72 00 20 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 2d 00 0d 00 0a 00 46 00 6f 00 75 00 6e 00 64}  //weight: 3, accuracy: High
        $x_1_2 = "Mozilla\\Firefox\\Profiles" ascii //weight: 1
        $x_1_3 = "logins.json" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_AMDA_2147931072_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.AMDA!MTB"
        threat_id = "2147931072"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 25 16 11 ?? 1f 10 63 20 ff 00 00 00 5f d2 9c 25 17 11 ?? 1e 63 20 ff 00 00 00 5f d2 9c 25 18 11 ?? 20 ff 00 00 00 5f d2 9c 6f ?? 00 00 0a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_GT_2147933436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.GT!MTB"
        threat_id = "2147933436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 01 11 01 6f 07 00 00 0a 11 01 6f 08 00 00 0a 6f 09 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_DCP_2147935947_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.DCP!MTB"
        threat_id = "2147935947"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 06 11 0f 11 0f 1b 5a 20 bb 00 00 00 61 d2 9c 00 11 0f 17 58 13 0f 11 0f 11 06 8e 69 fe 04 13 10 11 10}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_LTI_2147937039_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.LTI!MTB"
        threat_id = "2147937039"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 06 00 00 1b 11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 11 07 17 58 13 07 11 07 06 75 06 00 00 1b 8e 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_PBK_2147938293_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.PBK!MTB"
        threat_id = "2147938293"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 07 11 07 1f 11 5a 11 07 18 62 61 ?? ?? ?? ?? ?? 60 9e 11 07 17 58 13 07 11 07 06 ?? ?? ?? ?? ?? 8e 69 fe 04 13 08 11 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_MLI_2147938565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.MLI!MTB"
        threat_id = "2147938565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 1e 5d 16 fe 01 13 06 11 06 2c 0f 02 11 05 02 11 05 91 20 a9 00 00 00 61 b4 9c 11 05 17 d6 13 05 11 05 11 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_SnakeKeyLogger_TL_2147940580_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/SnakeKeyLogger.TL!MTB"
        threat_id = "2147940580"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "SnakeKeyLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 11 07 91 06 ?? ?? ?? ?? ?? 11 05 91 13 08 07 61 11 08 61 13 09 11 0c 1f ?? 91 11 0c 20 ?? ?? ?? ?? 91 59 13 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

