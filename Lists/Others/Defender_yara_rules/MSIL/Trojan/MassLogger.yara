rule Trojan_MSIL_MassLogger_GN_2147760436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.GN!MTB"
        threat_id = "2147760436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {01 0b 07 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 14 72 ?? ?? ?? 70 17 8d ?? ?? ?? 01 25 16 72 ?? ?? ?? 70 a2 14 14 28 ?? ?? ?? 0a 74 ?? ?? ?? 01 0c 00 08 14 1a 8d ?? ?? ?? 01 25 d0 ?? ?? ?? 04 28 ?? ?? ?? 0a 73 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 18 8d ?? ?? ?? 01 25 17 03 a2 14 14 28 ?? ?? ?? 0a 26 72 ?? ?? ?? ?? 0d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_GN_2147760436_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.GN!MTB"
        threat_id = "2147760436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 0c 19 8d ?? ?? ?? 01 13 06 11 06 16 7e ?? ?? ?? 04 a2 11 06 17 7e ?? ?? ?? 04 a2 11 06 18 20 ?? ?? ?? ?? 28 ?? ?? ?? 06 a2 11 06 73 ?? ?? ?? 06 [0-32] 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {17 13 05 17 13 06 19 8d ?? ?? ?? 01 13 07 11 07 16 7e ?? ?? ?? 04 a2 11 07 17 7e ?? ?? ?? 04 a2 11 07 18 72 ?? ?? ?? ?? a2 11 07 73 ?? ?? ?? 06 [0-32] 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_MSIL_MassLogger_RM_2147763799_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.RM!MTB"
        threat_id = "2147763799"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "oXCCFvgFvoMFCnfdtYEwdOHfBHtnA.resources" ascii //weight: 1
        $x_1_2 = "PpLYzkgfaYBngpiXMUeROfwGTnzE.resources" ascii //weight: 1
        $x_1_3 = "PxHmqfwUlXIcRAXxIAAcUbMcMkGj.resources" ascii //weight: 1
        $x_1_4 = "rUKPidMihJiyQHedSmumJFTtwtKtA.resources" ascii //weight: 1
        $x_1_5 = {57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 ?? ?? 2e 50 72 6f 70 65 72 74 69 65 73}  //weight: 1, accuracy: Low
        $x_1_6 = "bqocVYTRKxKJWXGLYgkKJhRancbMA.resources" ascii //weight: 1
        $x_1_7 = "RVzywHBbhheccROJrSfRnGjzcJmN.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_MSIL_MassLogger_SA_2147763803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.SA!MTB"
        threat_id = "2147763803"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wHIZWZTOEfkOAFCnOXKnkOwjuoLU.resources" ascii //weight: 1
        $x_1_2 = "scSVKGwfKLrAfdmOeFZNxTgRCEXC" ascii //weight: 1
        $x_1_3 = "PpEEfOBWMpjlWiEKhEwIbWlpHwTr.resources" ascii //weight: 1
        $x_1_4 = "YlAAwjFkQdxcLRhMugHSJoqFKqKv" ascii //weight: 1
        $x_1_5 = "Lime_Pony.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_RDA_2147912634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.RDA!MTB"
        threat_id = "2147912634"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 13 05 11 05 6f 80 00 00 0a 13 06 73 81 00 00 0a 0d 09 11 06 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_RDB_2147919302_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.RDB!MTB"
        threat_id = "2147919302"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 04 06 16 06 8e 69 6f 1c 00 00 0a 09 6f 1d 00 00 0a 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AML_2147920453_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AML!MTB"
        threat_id = "2147920453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 13 40 2b 23 00 03 11 3f 11 40 91 6f ?? ?? ?? 0a 00 11 14 1d 17 9c 11 0c 11 3f 11 40 91 58 13 0c 00 11 40 17 58 13 40 11 40 11 32 fe 04 13 41}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AML_2147920453_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AML!MTB"
        threat_id = "2147920453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 0b 2b 2d 02 06 07 28 ?? 00 00 06 0c 04 03 6f ?? 00 00 0a 59 0d 03 08 09 28 ?? 00 00 06 03 08 09 28 ?? 00 00 06 03 04 28 ?? 00 00 06 07 17 58 0b 07 02 6f}  //weight: 2, accuracy: Low
        $x_1_2 = "TicTacToeWinForms" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AML_2147920453_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AML!MTB"
        threat_id = "2147920453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 07 38 3b 01 00 00 00 02 11 05 11 07 6f ?? 00 00 0a 13 08 04 03 6f ?? 00 00 0a 59 13 09 07 72 fa 03 00 70 28 ?? 00 00 0a 2c 08 11 09 1f 64 fe 02 2b 01 16 13 0a 11 0a 2c 0d 00 11 09 1f 64 28 ?? 00 00 0a 13 09 00 11 09 19 fe 04 16 fe 01 13 0b 11 0b 2c 70}  //weight: 2, accuracy: Low
        $x_1_2 = "Vector_International" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AML_2147920453_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AML!MTB"
        threat_id = "2147920453"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FroggSecurityChecker.FroggAbout.resources" ascii //weight: 1
        $x_1_2 = "13f38eaa-447e-4059-8dbb-ab215d6a0eaa" ascii //weight: 1
        $x_2_3 = "powered by admin@frogg.fr" wide //weight: 2
        $x_2_4 = "Frogg Security Checker" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_MBXU_2147920462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.MBXU!MTB"
        threat_id = "2147920462"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CreateInstance" wide //weight: 5
        $x_4_2 = "DeveloperTools.QuickForms" wide //weight: 4
        $x_3_3 = "Split" ascii //weight: 3
        $x_2_4 = "GetPixel" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_MBXT_2147921633_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.MBXT!MTB"
        threat_id = "2147921633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 06 07 6f ?? 00 00 0a 0c 03 6f ?? 00 00 0a 19 58 04 fe ?? 16 fe ?? 0d 09 2c}  //weight: 2, accuracy: Low
        $x_1_2 = {43 00 72 00 65 00 61 00 74 00 65 00 49 00 6e 00 73 00 74 00 61 00 6e 00 63 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_MBXT_2147921633_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.MBXT!MTB"
        threat_id = "2147921633"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "CSE101_Final_Prep" wide //weight: 5
        $x_4_2 = {4c 00 6f 00 61 00 64}  //weight: 4, accuracy: High
        $x_3_3 = "Calculadora" wide //weight: 3
        $x_2_4 = "InvokeMember" ascii //weight: 2
        $x_1_5 = "Split" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AMA_2147922166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AMA!MTB"
        threat_id = "2147922166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 02 28 9f 00 00 06 72 39 1a 00 70 72 3d 1a 00 70 6f b1 00 00 0a 28 5b 00 00 06 7d ad 00 00 04 06 fe 06 b0 00 00 06 73 b2 00 00 0a 6f b3 00 00 0a 0c d0 6d 00 00 01 28 3a 00 00 0a 72 43 1a 00 70 17 8d 2d 00 00 01 25 16 d0 09 00 00 1b 28 3a 00 00 0a a2 28 b4 00 00 0a 25}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AOIA_2147930394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AOIA!MTB"
        threat_id = "2147930394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {59 91 61 02 08 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 02 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 08 17 58 0c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AHJA_2147931246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AHJA!MTB"
        threat_id = "2147931246"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 05 16 02 8e 69 6f ?? 00 00 0a 0d 2b 00 09 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AJJA_2147931380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AJJA!MTB"
        threat_id = "2147931380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0e 04 16 0e 04 8e 69 6f ?? 00 00 0a 0d 2b 00 09 2a}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_PLIMH_2147931746_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.PLIMH!MTB"
        threat_id = "2147931746"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 00 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 03 16 04 8e 69 6f ?? 00 00 0a 13 04 de 16}  //weight: 10, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AUJA_2147931897_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AUJA!MTB"
        threat_id = "2147931897"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0e 05 16 0e 05 8e 69 6f ?? 00 00 0a 0d 2b 00 09 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "AntiBossing" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AULA_2147933775_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AULA!MTB"
        threat_id = "2147933775"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 0b 07 28 ?? 00 00 0a 03 6f ?? 00 00 0a 6f ?? 00 00 0a 0c 06 08 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 6f ?? 00 00 0a 0e 06 16 0e 06 8e 69 6f ?? 00 00 0a 0d 2b 00 09 2a}  //weight: 3, accuracy: Low
        $x_1_2 = "AntiBossing" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AAD_2147933907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AAD!MTB"
        threat_id = "2147933907"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 13 04 73 ?? 00 00 0a 13 05 11 05 11 04 08 09 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 06 11 06 06 16 06 8e 69 6f ?? 00 00 0a 11 05 6f ?? 00 00 0a 13 07 dd}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_BN_2147934463_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.BN!MTB"
        threat_id = "2147934463"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 0f 00 28 ?? 00 00 0a 58 0f 00 28 ?? 00 00 0a 58 0a 06 19 5a 20 00 01 00 00 5d 0a 19 8d ?? 00 00 01 25 16 0f 00 28 ?? 00 00 0a 1f 55 61 d2 9c 25 17}  //weight: 4, accuracy: Low
        $x_1_2 = {a2 0b 02 03 04 6f ?? 00 00 0a 0c 0e 04 05 6f ?? 00 00 0a 59 0d 06 1c fe 04 16 fe 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_HHF_2147935384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.HHF!MTB"
        threat_id = "2147935384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 25 16 0f 00 28 ?? 00 00 0a 9c 25 17 0f 00 28 ?? 00 00 0a 9c 25 18 0f 00 28 ?? 00 00 0a 9c 6f ?? 00 00 0a 00 06 28 ?? 00 00 2b 00 2a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AFOA_2147936201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AFOA!MTB"
        threat_id = "2147936201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 07 8f 01 00 00 01 25 71 01 00 00 01 11 07 0e 04 58 05 59 20 ff 00 00 00 5f d2 61 d2 81 01 00 00 01 1d 13 10 38 ?? fe ff ff 11 07 17 59}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_ARPA_2147937375_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.ARPA!MTB"
        threat_id = "2147937375"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {02 11 05 11 06 6f ?? 00 00 0a 13 07 04 03 6f ?? 00 00 0a 59 13 08 07 72 a9 00 00 70 28 ?? 00 00 0a 2c 11 11 08 1f 64 31 0b 11 08 1f 64 28 ?? 00 00 0a 13 08 11 08 19 32 60}  //weight: 3, accuracy: Low
        $x_2_2 = {01 25 16 12 07 28 ?? 00 00 0a 9c 25 17 12 07 28 ?? 00 00 0a 9c 25 18 12 07 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AUPA_2147937710_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AUPA!MTB"
        threat_id = "2147937710"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 0c 94 13 0d 11 04 11 0d 19 5a 11 0d 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 11 0c 17 58 13 0c 11 0c 11 0b 75 ?? 00 00 1b 8e 69 32 c4}  //weight: 5, accuracy: Low
        $x_2_2 = {11 07 11 07 1f 11 5a 11 07 18 62 61 20 aa 00 00 00 60 9e 11 07 17 58 13 07 11 07 06 74 ?? 00 00 1b 8e 69 fe 04 13 08 11 08 2d cf}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_ABQA_2147937840_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.ABQA!MTB"
        threat_id = "2147937840"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {11 0a 11 0b 94 13 0c 00 11 04 11 0c 19 5a 11 0c 18 63 59 6a 58 13 04 11 04 11 04 1b 62 11 04 19 63 60 61 13 04 00 11 0b 17 58 13 0b 11 0b 11 0a 8e 69 32 cc}  //weight: 3, accuracy: High
        $x_2_2 = {06 11 06 11 06 1f 11 5a 11 06 18 62 61 20 aa 00 00 00 60 9e 00 11 06 17 58 13 06 11 06 06 8e 69 fe 04 13 07 11 07 2d d7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_BQ_2147939330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.BQ!MTB"
        threat_id = "2147939330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0e 04 03 19 8d ?? 00 00 01 25 16 12 09 28 ?? 00 00 0a 9c 25 17}  //weight: 2, accuracy: Low
        $x_2_2 = {8e 69 58 7e ?? 00 00 04 8e 69 5d 13 16 7e ?? 00 00 04 11 16 93 19 5d}  //weight: 2, accuracy: Low
        $x_1_3 = {04 25 2d 17 26 7e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_ALRA_2147939367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.ALRA!MTB"
        threat_id = "2147939367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {1a 25 2c 17 8d ?? 00 00 01 0b 06 07 16 1a 6f ?? ?? 00 0a 26 07 16 28 ?? ?? 00 0a 0c 06 16 73 ?? ?? 00 0a 0d 2b 36 8d ?? 00 00 01 2b 32 16 2b 33 2b 1c 2b 33 2b 34 2b 36 08 11 05 59 6f ?? ?? 00 0a 13 06 11 06 2c 0c 11 05 11 06 58 13 05 11 05 08 32 df 1b 2c ed 11 04 13 07 de 36 08 2b c7 13 04 2b ca 13 05 2b c9 09 2b ca 11 04 2b c8 11 05 2b c6}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_BR_2147939657_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.BR!MTB"
        threat_id = "2147939657"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 06 11 08 6f ?? 00 00 0a 13 09 04 03 6f ?? 00 00 0a 59 13 0a 11 0a 19 fe 04 16 fe 01 13 0d 11 0d 2c 6a 00 16 13 0e 2b 00 03 19 8d ?? 00 00 01 25 16 12 09 28 ?? 00 00 0a 9c 25 17 12 09 28 ?? 00 00 0a 9c 25 18 12 09}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_ACSA_2147939975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.ACSA!MTB"
        threat_id = "2147939975"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 1a 59 17 2c db 8d ?? 00 00 01 38 ?? 00 00 00 1d 2c e7 38 ?? 00 00 00 1a 07 16 07 8e 69 28 ?? 00 00 0a 06 28 ?? 00 00 06 0c 07 73 ?? 00 00 0a 0d 09 16 73 ?? 00 00 0a 13 04 16 13 05 2b 1e 1a 2c 25 11 04 08 11 05 06 11 05 59 6f ?? 00 00 0a 13 06 11 06 2c 0c 11 05 11 06 58 13 05 11 05 06 32 dd 11 05 06 2e 06 73 ?? 00 00 0a 7a 06 8d ?? 00 00 01 13 07 08 16 11 07 16 06 28 ?? 00 00 0a 11 07 13 08 de 1d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AHSA_2147940240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AHSA!MTB"
        threat_id = "2147940240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 08 02 07 6f ?? 00 00 0a 1f 20 5d 1f 09 58 1f 19 5d 1f 10 5a 02 07 17 58 6f ?? 00 00 0a 1f 20 5d 1f 09 58 1f 19 5d 58 d2 9c 07 18 58 0b 08 17 58 0c 08 06 8e 69 fe 04 0d 09 2d c4}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AISA_2147940326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AISA!MTB"
        threat_id = "2147940326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 13 04 11 04 09 06 07 6f ?? ?? 00 0a 17 73 ?? ?? 00 0a 13 05 16 2d 14 2b 38 2b 3a 16 03 8e 69 6f ?? ?? 00 0a 11 05 6f ?? ?? 00 0a 11 04 6f ?? ?? 00 0a 13 06 11 06 8e 69 28 ?? ?? 00 06 0c 11 06 16 08 16 11 06 8e 69 28 ?? ?? 00 0a 08 13 07 de 2c 11 05 2b c4 03 2b c3}  //weight: 5, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_WL_2147940421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.WL!MTB"
        threat_id = "2147940421"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0b 14 0c 73 16 00 00 0a 0d 73 17 00 00 0a 13 04 11 04 09 06 07 6f 18 00 00 0a 17 73 19 00 00 0a 13 05}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_BS_2147940595_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.BS!MTB"
        threat_id = "2147940595"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 18 5d 16 fe 01 0b 19 8d ?? 00 00 01 25 16}  //weight: 2, accuracy: Low
        $x_1_2 = {04 fe 04 2b 01 16}  //weight: 1, accuracy: High
        $x_1_3 = {5a 20 ff 00 00 00 5d}  //weight: 1, accuracy: High
        $x_1_4 = {1b fe 02 2b 01 16}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AVSA_2147940638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AVSA!MTB"
        threat_id = "2147940638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 06 11 08 6f ?? 00 00 0a 13 09 11 04 11 05 8e 69 6f ?? 00 00 0a 13 0b 11 0b 2c 39 00 00 11 05 13 0c 16 13 0d 2b 25 11 0c 11 0d 94 13 0e 00 11 0e 16 fe 04 13 0f 11 0f 2c 0b}  //weight: 5, accuracy: Low
        $x_2_2 = {59 13 0a 11 0a 19 fe 04 16 fe 01 13 10 11 10 2c 48 00 11 06 16 2f 07 11 08 16 fe 04 2b 01 16 13 11 11 11 2c 07 00 73 e7 00 00 0a 7a 03 12 09 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 09 28 ?? 00 00 0a 6f ?? 00 00 0a 00 03 12 09 28 ?? 00 00 0a 6f ?? 00 00 0a 00 00 2b 58 11 0a 16 fe 02 13 12 11 12 2c 4d 00 19 8d ?? 00 00 01 25 16 12 09 28 ?? 00 00 0a 9c 25 17 12 09 28 ?? 00 00 0a 9c 25 18 12 09 28 ?? 00 00 0a 9c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_ZUW_2147940765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.ZUW!MTB"
        threat_id = "2147940765"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 09 11 05 6f ?? 00 00 0a 13 08 00 de 0e 26 00 28 ?? 00 00 0a 13 08 dd 45 01 00 00 04 03 6f ?? 00 00 0a 59 13 09 11 04 7e ?? 00 00 0a 28 ?? 00 00 0a 13 0c 11 0c 2c 02 00 00 11 09 06 6f ?? 00 00 0a 17 58 fe 04 16 fe 01 13 0d 11 0d 2c 71 00 12 08 28 ?? 00 00 0a 16 61 d2 13 0e 12 08 28 ?? 00 00 0a 16 61 d2 13 0f 12 08 28 ?? 00 00 0a 16 61 d2 13 10 00 07 16 fe 03 13 11 11 11 2c 1f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_ZWW_2147940943_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.ZWW!MTB"
        threat_id = "2147940943"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 09 16 28 ?? 00 00 0a 13 04 08 16 73 ?? 00 00 0a 13 05 11 04 8d ?? 00 00 01 13 06 16 13 07 38 ?? 00 00 00 11 07 11 05 11 06 11 07 11 04 11 07 59 6f ?? 00 00 0a 58 13 07 11 07 11 04 32 e5 03 72 ?? 00 00 70 11 06 6f ?? 00 00 06 17 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AHTA_2147941047_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AHTA!MTB"
        threat_id = "2147941047"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 2c 06 06 8e 69 1a 2f 07 16 0b dd 8d 00 00 00 06 73 ?? 00 00 0a 0c 16 2d 44 2b 47 2b 48 2b 49 2b 4e 2b 4f 8d ?? 00 00 01 2b 4b 2b 4d 16 2b 4d 2b 52 11 04 02 16 11 05 09 28 ?? 00 00 06 de 0f 11 05 2c 0a 16 2d 07 11 05 6f ?? 00 00 0a dc 03 72 ?? ?? 00 70 11 04 28 ?? 00 00 06 17 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AMTA_2147941145_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AMTA!MTB"
        threat_id = "2147941145"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 8e 69 1a 2f 07 16 0b dd 8d 00 00 00 06 73 ?? 00 00 0a 0c 16 2d 44 2b 47 2b 48 2b 49 2b 4e 2b 4f 8d ?? 00 00 01 2b 4b 2b 4d 16 2b 4d 2b 52 16 09 11 05 02 11 04 28 ?? 00 00 06 de 0f 11 05 2c 0a 16 2d 07 11 05 6f ?? 00 00 0a dc 03 72 ?? 00 00 70 11 04 28 ?? 00 00 06 17 0b}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_CE_2147941441_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.CE!MTB"
        threat_id = "2147941441"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {08 17 94 2f 09 03 6f ?? 00 00 0a 04 32 b1 07 07 61 0b 09 17 58 0d 09 08 16 94 2f 09 03 6f ?? 00 00 0a 04}  //weight: 4, accuracy: Low
        $x_1_2 = {04 16 31 0c 02 03 7b ?? 00 00 04 6f ?? 00 00 0a 04 17 31 0c 02 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_ZQV_2147941479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.ZQV!MTB"
        threat_id = "2147941479"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1b 5d 0b 07 1a 2e 0e 07 19 2e 0a 07 18 2e 06 07 17 fe 01 2b 01 17 13 05 11 05 2c 02 16 0b 28 ?? 00 00 0a 17 fe 02 0c 19 8d ?? 00 00 1b 25 16 06 fe 06 43 00 00 06 73 ?? 00 00 0a a2 25 17 06 fe 06 44 00 00 06 73 ?? 00 00 0a a2 25 18 06 fe 06 45 00 00 06 73 ?? 00 00 0a a2 0d 06 09 07 9a 7d ?? 00 00 04 06 06 fe 06 46 00 00 06 73 ?? 00 00 0a 7d 4b 00 00 04 08 13 06 11 06 2c 0b}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_APUA_2147941879_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.APUA!MTB"
        threat_id = "2147941879"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {11 09 74 d1 00 00 01 02 74 ?? 00 00 1b 16 02 14 72 ?? ?? 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 6f ?? ?? 00 0a 16 13 11 2b af 11 09 75 ?? 00 00 01 6f ?? ?? 00 0a 11 08 74 ?? 00 00 01 6f ?? ?? 00 0a 0d de 49}  //weight: 4, accuracy: Low
        $x_3_2 = {0a 11 04 74 ?? 00 00 01 20 80 00 00 00 6f ?? ?? 00 0a 1e 13 0d 2b 86 11 04 75 ?? 00 00 01 19 6f ?? ?? 00 0a 11 04 74 ?? 00 00 01 08 75 ?? 00 00 1b 6f ?? ?? 00 0a 17 13 0d 38 ?? ff ff ff 11 04 74 ?? 00 00 01 08 75 ?? 00 00 1b 6f ?? ?? 00 0a 11 04 75 ?? 00 00 01 6f ?? ?? 00 0a 13 06 1f 09 13 0d 38}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_AEVA_2147942169_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.AEVA!MTB"
        threat_id = "2147942169"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {08 11 06 91 16 fe 01 13 07 11 07 2c 0c 08 11 06 20 ff 00 00 00 9c 00 2b 14 00 08 11 06 8f ?? 00 00 01 25 13 08 11 08 47 17 da b4 52 00 11 06 17 d6 13 06 11 06 11 05 31 c7}  //weight: 5, accuracy: Low
        $x_2_2 = {08 11 04 07 07 8e 69 17 da 11 04 da 91 9c 11 04 17 d6 13 04 11 04 09 31 e7}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_CG_2147943445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.CG!MTB"
        threat_id = "2147943445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {59 13 1d 73 ?? 00 00 0a 13 1e 11 1e 72 ?? ?? 00 70 12 1b 28 ?? 00 00 0a 12 1b 28 ?? 00 00 0a 58 12 1b 28 ?? 00 00 0a 58 6c}  //weight: 3, accuracy: Low
        $x_1_2 = {58 12 1b 28 ?? 00 00 0a 58 1f 0a 5a 58}  //weight: 1, accuracy: Low
        $x_1_3 = {11 1d 19 fe 04 16 fe 01 13 2a 11 2a 2c 5a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_PA_2147944390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.PA!MTB"
        threat_id = "2147944390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {25 47 09 11 08 58 1f 11 5a 20 ?? ?? 00 00 5d d2 61 d2 52 09 1f 1f 5a 08 11 08 91 58 20 ?? ?? 00 00 5d 0d 00 11 08 17 58 13 08}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_ZIS_2147944545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.ZIS!MTB"
        threat_id = "2147944545"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 12 00 02 11 2c 11 30 6f ?? 00 00 0a 13 31 11 17 12 31 28 ?? 00 00 0a 58 13 17 11 18 12 31 28 ?? 00 00 0a 58 13 18 11 19 12 31 28 ?? 00 00 0a 58 13 19 12 31}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_PGM_2147944756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.PGM!MTB"
        threat_id = "2147944756"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 11 31 11 34 6f ?? 00 00 0a 13 37 12 37 28 ?? 00 00 0a 06 61 d2 13 38 12 37 28 ?? 00 00 0a 06 61 d2 13 39 12 37 28 ?? 00 00 0a 06 61 d2 13 3a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_EANW_2147945209_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.EANW!MTB"
        threat_id = "2147945209"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 11 09 11 4f 16 9c 00 11 4f 17 58 13 4f 11 4f 1f 0a 11 09 8e 69 ?? ?? ?? ?? ?? fe 04 13 50 11 50 2d dd}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_EHJY_2147945212_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.EHJY!MTB"
        threat_id = "2147945212"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 11 10 1f 0a 58 13 10 11 0c 11 2c 1f 1f 5a 58 13 0c 11 0d 11 2c 61 13 0d 11 2c 1f 32 5d 16 fe 01 13 2d 11 2d 2c 20 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_EHKA_2147945218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.EHKA!MTB"
        threat_id = "2147945218"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {13 04 06 09 93 13 05 06 09 06 11 04 93 9d 06 11 04 11 05 9d 00 09 17 58 0d 09 06 8e 69 fe 04 13 06 11 06 2d cc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_MassLogger_ELLB_2147946275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/MassLogger.ELLB!MTB"
        threat_id = "2147946275"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "MassLogger"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5d 1c 58 13 3f 17 12 3b ?? ?? ?? ?? ?? 12 3b ?? ?? ?? ?? ?? 58 12 3b ?? ?? ?? ?? ?? 58 1f 7f 5b 58 13 40 11 40 1b fe 04 16 fe 01 13 41 12 3b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

