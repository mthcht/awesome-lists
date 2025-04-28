rule Trojan_MSIL_Xmrig_NE_2147828120_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NE!MTB"
        threat_id = "2147828120"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "C:\\Xcrcure\\xmrig.exe" wide //weight: 1
        $x_1_2 = "MsDtsServer.exe" wide //weight: 1
        $x_1_3 = "NewStartUp.lnk" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NEA_2147828314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NEA!MTB"
        threat_id = "2147828314"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$f554eebb-65bd-4fbe-a912-83b4c10ae54d" ascii //weight: 1
        $x_1_2 = "m@A@CMD" ascii //weight: 1
        $x_1_3 = "wKhK[YYOW]ST" ascii //weight: 1
        $x_1_4 = "C1908338681" ascii //weight: 1
        $x_1_5 = "CAD1094388875" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_AJMD_2147832276_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.AJMD!MTB"
        threat_id = "2147832276"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 9a 28 ?? ?? ?? 0a 0d 09 18 5d 2d 0e 07 08 09 1f 19 58 28 ?? ?? ?? 0a 9c 2b 0c 07 08 09 1f 0f 59 28 ?? ?? ?? 0a 9c 08 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NEB_2147833832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NEB!MTB"
        threat_id = "2147833832"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7e 03 00 00 04 06 7e 03 00 00 04 06 91 06 61 00 23 00 00 00 00 00 00 00 40 23 00 00 00 00 00 40 55 40 5a 28 19 00 00 0a 61 d2 9c 06 17 58 0a 06 7e 03 00 00 04 8e 69 fe 04}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_AHRL_2147835873_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.AHRL!MTB"
        threat_id = "2147835873"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 04 11 0d 9a 6f ?? ?? ?? 0a 11 05 11 0e 9a 28 ?? ?? ?? 0a 13 0f 11 0f 2c 11 00 28 ?? ?? ?? 0a 13 10 11 10 6f}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_ABHV_2147838444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.ABHV!MTB"
        threat_id = "2147838444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 06 16 73 ?? ?? ?? 0a 73 ?? ?? ?? 0a 0c 08 07 6f ?? ?? ?? 0a 07 6f ?? ?? ?? 0a 0d de 1e 08 2c 06 08 6f ?? ?? ?? 0a dc}  //weight: 1, accuracy: Low
        $x_1_2 = "WindowsFormsApp1.Properties.Resources" wide //weight: 1
        $x_1_3 = "Uvotnztujclaaja" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_GCE_2147838670_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.GCE!MTB"
        threat_id = "2147838670"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "U0hFTEwk" ascii //weight: 1
        $x_1_2 = "U0hFTEwl" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "c45760d965c3dbe9ea61492259c33b9cb" ascii //weight: 1
        $x_1_5 = "set_UseShellExecute" ascii //weight: 1
        $x_1_6 = "CreateDecryptor" ascii //weight: 1
        $x_1_7 = "SHELL.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NEAC_2147838961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NEAC!MTB"
        threat_id = "2147838961"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "4a2502be-90cd-40b4-a877-2ab78982d2ff" ascii //weight: 5
        $x_3_2 = "MainPart.MainL.resources" ascii //weight: 3
        $x_3_3 = "MainPart.exe" ascii //weight: 3
        $x_2_4 = "Confuser.Core 1.2.0+4110faee9d" ascii //weight: 2
        $x_2_5 = "set_UseShellExecute" ascii //weight: 2
        $x_2_6 = "ProcessWindowStyle" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NEAD_2147839869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NEAD!MTB"
        threat_id = "2147839869"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {16 0a 2b 3a 00 28 12 00 00 0a 72 25 00 00 70 28 09 00 00 06 6f 13 00 00 0a 28 14 00 00 0a 0b 07 16 07 8e 69 28 15 00 00 0a 07 0c de 17 26}  //weight: 10, accuracy: High
        $x_5_2 = "https://cdn.discordapp.com/attachments" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NEAE_2147839877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NEAE!MTB"
        threat_id = "2147839877"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 15 00 00 06 72 13 00 00 70 28 0f 00 00 06 28 16 00 00 06 28 0e 00 00 0a 28 02 00 00 2b 28 03 00 00 2b 13 01}  //weight: 10, accuracy: High
        $x_2_2 = "WindowsFormsApp25" ascii //weight: 2
        $x_2_3 = "newone1" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NEAF_2147840317_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NEAF!MTB"
        threat_id = "2147840317"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6f 54 00 00 0a 14 19 8d 01 00 00 01 0a 06 16 02 a2 06 17 03 a2 06 18 04 a2 06 6f 55 00 00 0a 26 de 03}  //weight: 10, accuracy: High
        $x_2_2 = "xKUigAMqPqMPvD9Fu0TbEA==" wide //weight: 2
        $x_2_3 = "uc5T1vhlLUW3Bl106wOJjQ==" wide //weight: 2
        $x_2_4 = "ZWM2MzJmZDktMTY5NC00ZjRhLTliZmYtZjIwNjAwZTM3OTgx" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_RDA_2147840609_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.RDA!MTB"
        threat_id = "2147840609"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "4c7ad027-21df-4f2a-9653-b0fc63c7dbae" ascii //weight: 1
        $x_1_2 = "HashVaultXMRigMiner" ascii //weight: 1
        $x_1_3 = "//telegra.ph/vault-workers-controller-3-11-11" wide //weight: 1
        $x_1_4 = "hncxm.exe" wide //weight: 1
        $x_1_5 = "GOMXrig" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NEAG_2147840980_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NEAG!MTB"
        threat_id = "2147840980"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {09 11 04 18 5b 07 11 04 18 6f 25 00 00 0a 1f 10 28 26 00 00 0a 9c 11 04 18 58 13 04 11 04 08 32 df}  //weight: 10, accuracy: High
        $x_5_2 = "LWindowsFormsApp76oad" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_CBB_2147841052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.CBB!MTB"
        threat_id = "2147841052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "svchost.exe" ascii //weight: 2
        $x_1_2 = "Chrome" ascii //weight: 1
        $x_1_3 = "sHx+TA6SKx1+M2bGKD5LLg==" ascii //weight: 1
        $x_1_4 = "MFako/pCXJ/ox/6vKeIvoA==" ascii //weight: 1
        $x_1_5 = "Q/1MuQg1OxK1LbAQx9lEEg==" ascii //weight: 1
        $x_1_6 = "tlTaBInKx9x0DQzyfboVgA==" ascii //weight: 1
        $x_1_7 = "Rfc2898DeriveBytes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_CBC_2147841053_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.CBC!MTB"
        threat_id = "2147841053"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {28 03 00 00 06 28 02 00 00 06 28 ?? 00 00 0a 72 ?? ?? ?? 70 28 03 00 00 06 6f ?? 00 00 0a 02 1f 18 6f ?? 00 00 0a 14 03 6f ?? 00 00 0a a5 3a 00 00 01 0a de}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_AX_2147842666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.AX!MTB"
        threat_id = "2147842666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 14 0b 14 0c 14 0d 28 ?? ?? ?? 0a 1a 33 0e 72 32 0f 00 70 0c 72 7c 0f 00 70 0d 2b 0c 72 98 0f 00 70 0c 72 e2 0f 00 70 0d 06 08 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_AX_2147842666_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.AX!MTB"
        threat_id = "2147842666"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {2b 2c 1b 2d 1e 26 2b 2d 2b 32 2b 33 72 b5 00 00 70 7e 4c 00 00 0a 2b 2e 2b 33 18 2d 0d 26 dd 56 00 00 00 2b 2f 15 2c f6 2b dc 2b 2b 2b f0 28 ?? ?? ?? 06 2b cd 28 ?? ?? ?? 0a 2b cc 07 2b cb}  //weight: 2, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "WindowsFormsApp67" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NMR_2147842959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NMR!MTB"
        threat_id = "2147842959"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {58 13 06 11 0c 1f 18 64 d2 9c 09 11 0b 8f ?? ?? ?? 01 25 4b 11 0c 61 54 11 0d 20 ?? ?? ?? 00 5a 20 e3 08 f9 74 61}  //weight: 5, accuracy: Low
        $x_1_2 = "JITStarter" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_CZX_2147843351_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.CZX!MTB"
        threat_id = "2147843351"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 11 00 00 06 0a 28 ?? ?? ?? ?? 06 6f ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0b dd}  //weight: 5, accuracy: Low
        $x_5_2 = {02 06 91 0c 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 06 07 32}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_AXM_2147843424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.AXM!MTB"
        threat_id = "2147843424"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 11 00 00 06 0a 28 02 00 00 0a 06 6f 03 00 00 0a 28 04 00 00 0a 28 03 00 00 06 0b dd 03 00 00 00 26 de db 07 2a}  //weight: 2, accuracy: High
        $x_1_2 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NEAH_2147843445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NEAH!MTB"
        threat_id = "2147843445"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 28 11 00 00 06 0a 28 02 00 00 0a 06 6f 03 00 00 0a 28 04 00 00 0a 28 03 00 00 06 0b dd 03 00 00 00 26 de db 07 2a}  //weight: 10, accuracy: High
        $x_5_2 = "ChinhDo.Transactions" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_PSIV_2147844987_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.PSIV!MTB"
        threat_id = "2147844987"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 ff 00 00 0a 72 d4 03 00 70 28 00 01 00 0a 6f 01 01 00 0a 13 0c 08 28 0d 00 00 0a 2d 10 08 11 0c 28 02 01 00 0a 16 13 16 dd bc 02 00 00 11 05 11 0c 6f 03 01 00 0a 26 14 13 0d}  //weight: 2, accuracy: High
        $x_1_2 = "JGVudjpQU0V4ZXVjdGlvblBvbGljeVByZWZlcmVybmNlPSJieXBhc3MiDQo" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_PSML_2147846444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.PSML!MTB"
        threat_id = "2147846444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 08 9a 72 ee 00 00 70 6f 1e 00 00 0a 2c 0c 11 05 11 08 72 fe 00 00 70 a2 2b 4b 11 05 11 08 9a 72 2a 01 00 70 6f 1e 00 00 0a 2c 0c 11 05 11 08 72 38 01 00 70}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_PSNL_2147847621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.PSNL!MTB"
        threat_id = "2147847621"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 d3 6c 00 70 14 28 7e 00 00 06 1c 2d 17 26 28 88 00 00 0a 28 39 02 00 06 74 5b 00 00 1b 6f 89 00 00 0a 2b 07 28 8a 00 00 0a 2b e3 2a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NG_2147851005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NG!MTB"
        threat_id = "2147851005"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 0a 00 00 06 75 ?? 00 00 1b 6f ?? 00 00 0a 0a 06 14 28 ?? 00 00 0a 39 ?? 00 00 00 d0 ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 06 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 06 14 6f ?? 00 00 0a 75 ?? 00 00 1b}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp30.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NMG_2147851877_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NMG!MTB"
        threat_id = "2147851877"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 36 00 00 0a 13 0c 06 16 9a 7e ?? 00 00 04 06 17 9a 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 13 0b 11 0c 02 11 0b 02 8e b7 11 0b da 6f ?? 00 00 0a 11 0c 6f ?? 00 00 0a 28 ?? 00 00 06 0b de 36}  //weight: 5, accuracy: Low
        $x_1_2 = "Craxs Rat Loader" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_NIG_2147891687_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.NIG!MTB"
        threat_id = "2147891687"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {73 48 00 00 0a 13 33 11 33 73 ?? 00 00 0a 28 ?? 00 00 0a 03 6f ?? 00 00 0a 16 28 ?? 00 00 0a 03 6f ?? 00 00 0a 8e b7 6f ?? 00 00 0a 6f ?? 00 00 0a 11 33 18 6f ?? 00 00 0a 11 33 17 6f ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_1_2 = "Windows Defender Module Service" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_ABDX_2147896490_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.ABDX!MTB"
        threat_id = "2147896490"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 9b 00 00 70 0b 7e 10 00 00 04 06 7e 0f 00 00 04 72 a3 00 00 70 07 72 e7 00 00 70 28 40 00 00 06 28 45 00 00 06 26 7e 11 00 00 04 06 28 4a 00 00 06 0c 7e 13 00 00 04 7e 12 00 00 04 07 72 eb 00 00 70 28 4f 00 00 06 28 54 00 00 06 00 72 0d 01 00 70}  //weight: 1, accuracy: High
        $x_1_2 = "//raw.githubusercontent.com/drissmlds/CryptoTest/main/SetupENC.exe" wide //weight: 1
        $x_1_3 = "SetupENC.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_PSBL_2147899326_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.PSBL!MTB"
        threat_id = "2147899326"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PaddingMode" ascii //weight: 1
        $x_1_2 = "CryptoStreamMode" ascii //weight: 1
        $x_1_3 = "CipherMode" ascii //weight: 1
        $x_2_4 = "_4SzLknGaMKac6TS4AvUmXkFpWLe" ascii //weight: 2
        $x_2_5 = "_9AU5AUicrIEm6TtSJovDWK4qXLe" ascii //weight: 2
        $x_2_6 = "_fee7ajIQjzDx8U5hjzBq1C8upXe" ascii //weight: 2
        $x_2_7 = "_6jnuCzyxFZA1LWwEU69nWbXAFYe" ascii //weight: 2
        $x_2_8 = "IlKdDrCvOSxSdTCJaKAYypbe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_PSBQ_2147899330_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.PSBQ!MTB"
        threat_id = "2147899330"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 7f 00 00 0a 28 59 00 00 0a 7e 24 00 00 04 6f 80 00 00 0a 6f 81 00 00 0a 0a}  //weight: 5, accuracy: High
        $x_5_2 = {00 8d 44 00 00 01 0b 28 56 00 00 06 0c 7e 18 00 00 04 06 07 28 0e 00 00 06 28 46 00 00 06 28 01 00 00 0a 3a 84 02 00 00 7e 30 00 00 04 28 69 00 00 0a 3a 0f 00 00 00 7e 06 00 00 04 7e 30 00 00 04 28 34 00 00 06 7e 30 00 00 04 73 64 00 00 0a 28 a5 00 00 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_PSBZ_2147899333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.PSBZ!MTB"
        threat_id = "2147899333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {00 06 02 07 1e 6f 39 ?? ?? ?? 18 28 3a ?? ?? ?? 6f 3b ?? ?? ?? 00 00 07 1e 58 0b 07 02 6f 3c ?? ?? ?? fe 04 0c 08 2d d8 28 3d ?? ?? ?? 06 6f 3e ?? ?? ?? 6f 3f ?? ?? ?? 0d 2b 00 09 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_INAA_2147905685_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.INAA!MTB"
        threat_id = "2147905685"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8e 69 5d 1f 09 58 1f 0c 58 1f 15 59 1b 58 1b 59 91 61 ?? 06 1a 58 4a 20 0e 02 00 00 58 20 0d 02 00 00 59 ?? 8e 69 5d 1f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_WDAA_2147920776_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.WDAA!MTB"
        threat_id = "2147920776"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D2BB470292B966943A6B3262AFA5F72E" ascii //weight: 1
        $x_1_2 = "N6B8F48F79DFB560FB6774B85877E3DF" ascii //weight: 1
        $x_1_3 = "NABA7E1CB7C72BBEE1EBF79N795C315C" ascii //weight: 1
        $x_1_4 = "NABCEF040FBE65EDEN314C5NEE6FNDNF" ascii //weight: 1
        $x_1_5 = "N2665NC04490D795B9AFCE9EB0596F11" ascii //weight: 1
        $x_1_6 = "ND658475C841A6BN5A0C735A73NC7F74" ascii //weight: 1
        $x_2_7 = "DB6E7B19ECF2B39238AC22F8CFB36FA8.resources" wide //weight: 2
        $x_2_8 = "FakeMinerVirusExperiment.Resources" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_AXR_2147925472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.AXR!MTB"
        threat_id = "2147925472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {25 47 11 00 11 01 11 00 8e 69 5d 91 11 01 1f 63 58 11 00 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2}  //weight: 2, accuracy: High
        $x_1_2 = "password99" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Xmrig_AXR_2147925472_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Xmrig.AXR!MTB"
        threat_id = "2147925472"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Xmrig"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 5b 00 00 70 28 ?? 00 00 0a 0b 28 ?? 00 00 0a 0c 08 06 6f ?? 00 00 0a 08 07 6f ?? 00 00 0a 73 05 00 00 0a 0d 09 08 6f ?? 00 00 0a 17 73 07 00 00 0a 13 04 11 04 7e 01 00 00 04 16 7e 01 00 00 04 8e 69 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

