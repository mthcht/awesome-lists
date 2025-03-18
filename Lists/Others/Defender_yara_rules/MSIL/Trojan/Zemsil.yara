rule Trojan_MSIL_Zemsil_RPZ_2147850134_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.RPZ!MTB"
        threat_id = "2147850134"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EdenTestMethod" ascii //weight: 1
        $x_1_2 = "ExecuteShellCode" ascii //weight: 1
        $x_1_3 = "CpuUsage" ascii //weight: 1
        $x_1_4 = "PanelShellCodeEncryptionModule" ascii //weight: 1
        $x_1_5 = "PanelShellCodeLoaderModule" ascii //weight: 1
        $x_1_6 = "CurrentComputerName" ascii //weight: 1
        $x_1_7 = "EdenProjectConfig" ascii //weight: 1
        $x_1_8 = "TestWebShell" ascii //weight: 1
        $x_1_9 = "explorer" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SK_2147851333_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SK!MTB"
        threat_id = "2147851333"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 22 11 1a 11 1c 58 11 1b 11 1d 58 6f ?? ?? ?? 0a 13 5f 12 5f 28 ?? ?? ?? 0a 13 24 11 1f 11 1e 11 24 9c 11 1e 17 58 13 1e 11 1d 17 58 13 1d 11 1d 17 fe 04 13 25 11 25 2d c6}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SM_2147851870_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SM!MTB"
        threat_id = "2147851870"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hemphill.Resources" ascii //weight: 1
        $x_1_2 = "tornillo4" ascii //weight: 1
        $x_1_3 = "\\source\\repos\\EquinoxGniess\\Lending_Management_System\\Finals\\accounts.accdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SL_2147852030_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SL!MTB"
        threat_id = "2147852030"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 13 11 0f 8f 1c 00 00 01 25 47 7e 03 00 00 04 19 11 0f 5f 19 62 1f 1f 5f 63 d2 61 d2 52 17 11 0f 58 13 0f 11 0f 11 13 8e 69 33 d4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SO_2147892530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SO!MTB"
        threat_id = "2147892530"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {75 01 00 00 1b 0a 06 8e 69 8d 05 00 00 01 0b 16 0c 38 16 00 00 00 07 08 06 08 91 72 01 00 00 70 28 ?? ?? ?? 0a 59 d2 9c 08 17 58 0c 08 06 8e 69 32 e4}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SQ_2147894242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SQ!MTB"
        threat_id = "2147894242"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 09 02 09 6f ?? ?? ?? 0a 03 09 07 5d 6f ?? ?? ?? 0a 61 d1 9d 09 17 58 0d 09 06 32 e3}  //weight: 2, accuracy: Low
        $x_2_2 = "xorStub.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SS_2147898760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SS!MTB"
        threat_id = "2147898760"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Win_Forms_Collaboration.FrmPocetna.resources" ascii //weight: 2
        $x_2_2 = "$4c24cf3f-98e8-4f63-b64d-e08cf793c590" ascii //weight: 2
        $x_2_3 = "Visual N-Queens Solver" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SV_2147903200_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SV!MTB"
        threat_id = "2147903200"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 1f 16 5d 91 61 13 0a 11 0a 07 08 17 58 09 5d 91 59 20 00 01 00 00 58 13 0b 07 11 04 11 0b 20 00 01 00 00 5d d2 9c 11 06 07 11 04 91 6f 4c 00 00 0a 08 17 58 0c}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SW_2147903201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SW!MTB"
        threat_id = "2147903201"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 1f 16 5d 91 61 13 0b 11 0b 07 06 17 58 11 04 5d 91 59 20 00 01 00 00 58 13 0c 07 11 05 11 0c 20 00 01 00 00 5d d2 9c 11 06 07 11 05 91 6f 69 00 00 0a 06 17 58 0a 06 11 04 11 07 17 58 5a fe 04 13 0d 11 0d 2d 9b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SA_2147911838_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SA!MTB"
        threat_id = "2147911838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 1a 5d 16 fe 01 0d 09 2c 0a 02 08 02 08 91 1f 3d 61 b4 9c 08 17 d6 0c 08 07 31 e4}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SA_2147911838_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SA!MTB"
        threat_id = "2147911838"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {00 02 03 04 06 28 53 00 00 06 00 00 06 17 58 0a 06 02 6f 78 00 00 0a fe 04 0b 07 2d e3}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SB_2147912612_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SB!MTB"
        threat_id = "2147912612"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1b 2c 16 07 72 1b 45 00 70 73 a5 01 00 0a 6f 60 08 00 0a 6f 53 01 00 0a 0c 73 73 04 00 0a 0d}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_ARA_2147913013_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.ARA!MTB"
        threat_id = "2147913013"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 06 07 91 7e 05 00 00 04 07 7e 05 00 00 04 8e 69 5d 91 61 d2 9c 07 17 58 0b 07 06 8e 69 32 df}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_ABW_2147913941_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.ABW!MTB"
        threat_id = "2147913941"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SelfInjector" ascii //weight: 1
        $x_1_2 = "ShellcodeInject" ascii //weight: 1
        $x_1_3 = "RemoteInjector" ascii //weight: 1
        $x_1_4 = "SpawnInjector" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_AW_2147915390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.AW!MTB"
        threat_id = "2147915390"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "HP.exe" wide //weight: 1
        $x_1_2 = "powershell -Command Add-MpPreference -ExclusionPath C:" ascii //weight: 1
        $x_1_3 = "ObfuscatorAIO - https://github.com/123Studios" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SF_2147915521_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SF!MTB"
        threat_id = "2147915521"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {09 08 11 04 18 6f 0a 00 00 0a 1f 10 28 0b 00 00 0a 6f 0c 00 00 0a 11 04 18 58 13 04 11 04 08 6f 0d 00 00 0a 32 da}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SG_2147917682_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SG!MTB"
        threat_id = "2147917682"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "server1.exe" ascii //weight: 2
        $x_2_2 = "2024 Display Driver" ascii //weight: 2
        $x_2_3 = "$cc7fad03-816e-432c-9b92-001f2d378392" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SI_2147917684_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SI!MTB"
        threat_id = "2147917684"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 17 58 0b 07 06 8e 69 fe 04 13 06 11 06 2d ce}  //weight: 2, accuracy: High
        $x_1_2 = "BombosForm.Form1.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Zemsil_SJ_2147917688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Zemsil.SJ!MTB"
        threat_id = "2147917688"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Zemsil"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 07 06 11 07 8e 69 5d 91 13 0b 07 06 91 11 0b 61 13 0c 06 17 58 09 5d 13 0d 07 11 0d 91 13 0e 16 13 05 2b 55}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

