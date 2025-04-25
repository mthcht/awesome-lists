rule Trojan_MSIL_Redcap_2147818436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap!MTB"
        threat_id = "2147818436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "://github.com/dehoisted/Bat2Exe" wide //weight: 1
        $x_1_2 = "profile%" wide //weight: 1
        $x_1_3 = "tokens=*" wide //weight: 1
        $x_1_4 = "delims=" wide //weight: 1
        $x_1_5 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789" wide //weight: 1
        $x_1_6 = "GetTempPath" ascii //weight: 1
        $x_1_7 = "GetRandomString" ascii //weight: 1
        $x_1_8 = "AppendAllText" ascii //weight: 1
        $x_1_9 = "Bat2Exe" ascii //weight: 1
        $x_1_10 = "official_bat2exe_github" ascii //weight: 1
        $x_1_11 = "UseShellExecute" ascii //weight: 1
        $x_1_12 = "TASKKILL" wide //weight: 1
        $x_1_13 = "cookies" wide //weight: 1
        $x_1_14 = "erase" wide //weight: 1
        $x_1_15 = "attrib" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_RDA_2147839571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.RDA!MTB"
        threat_id = "2147839571"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "c317a0d8-fe8b-4bd6-af13-b23016d96213" ascii //weight: 1
        $x_1_2 = "ShellRunnerNuma" ascii //weight: 1
        $x_1_3 = "C:\\Users\\yukan\\source\\repos\\ShellRunner\\ShellRunnerNuma\\obj\\x64\\Debug\\ShellRunnerNuma.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_NRD_2147840041_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.NRD!MTB"
        threat_id = "2147840041"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 23 00 00 70 02 7b ?? 00 00 04 6f ?? 00 00 06 72 ?? 00 00 70 28 ?? 00 00 0a 02 7b ?? 00 00 04 73 ?? 00 00 0a 7d ?? 00 00 04 02 7b ?? 00 00 04 6f ?? 00 00 0a 00 02 7b ?? 00 00 04 6f ?? 00 00 0a 0a 06 6f ?? 00 00 0a 0b 07 2c 1d 00 06 6f ?? 00 00 0a 26 02 06 16 6f ?? 00 00 0a 6f ?? 00 00 0a 7d ?? 00 00 04}  //weight: 5, accuracy: Low
        $x_1_2 = "Crackers" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_ACP_2147844447_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.ACP!MTB"
        threat_id = "2147844447"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 8b 00 00 70 28 ?? ?? ?? 06 17 2d 1c 26 28 ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 1a 2d 06 26 de 09 0a 2b e2 0b 2b f8 26 de cd}  //weight: 1, accuracy: Low
        $x_1_2 = {0b 2b f8 02 06 91 1e 2d 15 26 02 06 02 07 91 9c 02 07 08 9c 06 17 58 0a 07 17 59 0b 2b 03 0c 2b e9 06 07 32 de}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_MBDD_2147845446_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.MBDD!MTB"
        threat_id = "2147845446"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$d929c003-e629-4656-b413-4877844f6d65" ascii //weight: 1
        $x_1_2 = "MyWi3e.Properties.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_RDC_2147845972_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.RDC!MTB"
        threat_id = "2147845972"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cd8ba96f-021d-487d-8fa6-e80cab88e164" ascii //weight: 1
        $x_2_2 = {8e 69 5d 91 61 d2 9c 00 06 06 4a 17 58 54}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PSNF_2147847077_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PSNF!MTB"
        threat_id = "2147847077"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {1f fc 6a 17 6f c9 00 00 0a 26 72 6f 46 00 70 28 c4 00 00 0a 07 6f ca 00 00 0a 13 07 08 11 07 16 11 07 8e 69 6f cb 00 00 0a 00 06 17}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PSRO_2147850751_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PSRO!MTB"
        threat_id = "2147850751"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {28 19 00 00 0a 2c 23 72 87 00 00 70 72 99 00 00 70 73 15 00 00 0a 25 17 6f 16 00 00 0a 25 16 6f 17 00 00 0a 28 18 00 00 0a 26 20 00 20 00 00 0b 72 a9 00 00 70 23 00 00 00 00 00 00 00 40 0c 72 ab 00 00 70 28 1a 00 00 0a 26 1f 1a 28 1b 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PSSA_2147850762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PSSA!MTB"
        threat_id = "2147850762"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {72 97 02 00 70 28 11 00 00 0a 72 b3 02 00 70 28 12 00 00 0a 26 2b 0a 72 f1 02 00 70 28 11 00 00 0a 20 88 13 00 00 28 13 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PSSN_2147851115_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PSSN!MTB"
        threat_id = "2147851115"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 6f 3d 00 00 0a 0c 7e 1d 00 00 04 28 3e 00 00 0a 74 18 00 00 01 0d 09 13 04 11 04 72 85 02 00 70 6f 3f 00 00 0a 00 11 04 14}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PSSY_2147851456_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PSSY!MTB"
        threat_id = "2147851456"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 72 6b 00 00 70 72 7b 00 00 70 28 07 00 00 06 02 72 6b 00 00 70 72 c7 00 00 70 28 07 00 00 06 02 7b 19 00 00 04 16 6f 2f 00 00 0a 02 7b 19 00 00 04 6f 30 00 00 0a 02}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_ARD_2147851551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.ARD!MTB"
        threat_id = "2147851551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 04 16 13 05 2b 30 11 04 11 05 9a 13 06 00 11 06 72 bd 02 00 70 6f ?? ?? ?? 0a 13 07 11 07 13 08 11 08 2c 0b 00 06 11 06 6f ?? ?? ?? 0a 00 00 00 11 05 17 58 13 05 11 05 11 04 8e 69 32 c8}  //weight: 2, accuracy: Low
        $x_1_2 = "HboMax2.0.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PSUA_2147852257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PSUA!MTB"
        threat_id = "2147852257"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6f 25 00 00 0a 14 17 8d 11 00 00 01 25 16 11 08 07 17 9a 74 1f 00 00 01 28 27 00 00 0a a2 6f 26 00 00 0a 74 03 00 00 1b 13 0d 11 0b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PSVY_2147888880_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PSVY!MTB"
        threat_id = "2147888880"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 16 28 89 00 00 0a 0a 06 28 ?? 00 00 0a 00 20 00 e1 f5 05 6a 28 ?? 00 00 0a 00 28 ?? 00 00 0a 00 20 e8 03 00 00 28 ?? 00 00 0a 00 00 de 05}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_AR_2147888892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.AR!MTB"
        threat_id = "2147888892"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {25 16 1f 7c 9d 6f ?? ?? ?? 0a 16 9a 13 06 11 06 17 8d ?? 00 00 01 25 16 1f 20 9d 6f ?? ?? ?? 0a 16 9a 6f ?? ?? ?? 0a 13 18 11 06 11 18}  //weight: 2, accuracy: Low
        $x_1_2 = "\\PC\\source\\repos\\Stealer try" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PSWI_2147889355_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PSWI!MTB"
        threat_id = "2147889355"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a2 25 1e 72 45 14 00 70 a2 28 ?? 00 00 0a 6f ?? 00 00 0a 0a 7e 11 00 00 04 28 ?? 00 00 0a 74 16 00 00 01 0b 07}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_RDD_2147890118_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.RDD!MTB"
        threat_id = "2147890118"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cd3bf541-7fcf-4bde-b243-f9d877bb18b9" ascii //weight: 1
        $x_1_2 = "SendUsbKey" ascii //weight: 1
        $x_1_3 = "Sendinfo" ascii //weight: 1
        $x_1_4 = "checkEnableLUA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_RDE_2147892496_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.RDE!MTB"
        threat_id = "2147892496"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {08 11 08 91 08 11 08 8f 1d 00 00 01 25 47 11 07 61 d2 52 13 07 11 08 17 58 13 08}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PTCO_2147897339_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PTCO!MTB"
        threat_id = "2147897339"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 06 6f 66 00 00 0a 0d 09 28 ?? 00 00 0a 0c 28 ?? 00 00 06 6f 68 00 00 0a 6f 69 00 00 0a 72 83 02 00 70 28 ?? 00 00 0a 0b}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_NRC_2147897384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.NRC!MTB"
        threat_id = "2147897384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 be 00 00 0a 16 13 18 dd ?? ?? 00 00 11 13 7b ?? ?? 00 04 11 0b 6f ?? ?? 00 0a 26 14 13 0c 72 ?? ?? 00 70 73 ?? ?? 00 0a 13 0d 11 07 13 0e}  //weight: 5, accuracy: Low
        $x_1_2 = "FirefoxPasswordGrabber.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_NRC_2147897384_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.NRC!MTB"
        threat_id = "2147897384"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 1a 00 00 01 13 04 7e ?? 00 00 04 11 04 16 11 04 8e 69 6f ?? 00 00 0a 13 05 28 ?? 00 00 0a 11 04 16 11 05 6f ?? 00 00 0a 13 06 09 6f ?? 00 00 0a 11 06 6f ?? 00 00 0a 09 6f ?? 00 00 0a 2c bb}  //weight: 5, accuracy: Low
        $x_1_2 = "cppExecutablePath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_PTCS_2147897436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.PTCS!MTB"
        threat_id = "2147897436"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {1f 40 d6 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 02 6f 34 00 00 06 0c 08 08 6f 72 00 00 0a 06 28 ?? 00 00 0a 07 72 e3 00 00 70 28 ?? 00 00 0a 6f 75 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_NN_2147900903_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.NN!MTB"
        threat_id = "2147900903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {64 0b 61 20 95 ?? ?? ?? 07 61 0b 0a ?? ?? ?? ?? ?? 07 5a 0b 02 07 ?? ?? ?? ?? ?? 61 0b 02 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_NN_2147900903_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.NN!MTB"
        threat_id = "2147900903"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {17 64 0a 07 06 59 1f 1f 64 13 04 07 06 11 04 17 59 5f 59 0b 08 17 62 17 11 04 59 60 0c 06 20 00 ?? ?? ?? 41 15 ?? ?? ?? 07 1e 62 02 7b 62 01 ?? ?? 6f 0f 02 ?? ?? d2 60 0b 06 1e 62 0a 09 17 59 0d 09 16}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_GMZ_2147900942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.GMZ!MTB"
        threat_id = "2147900942"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {13 05 11 05 2c 2b 00 11 04 72 03 37 00 70 06 72 6b 36 00 70 6f ?? ?? ?? 0a 06 72 77 36 00 70 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 13 04 00 72 35 37 00 70 11 04 28 ?? ?? ?? 0a 26}  //weight: 10, accuracy: Low
        $x_1_2 = "get_baseline_clear_black_18dp1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_GZZ_2147901894_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.GZZ!MTB"
        threat_id = "2147901894"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {06 60 0a 6f ?? ?? ?? 06 06 20 ?? ?? ?? ?? 5e 0a 28 ?? ?? ?? 06 20 ?? ?? ?? ?? 06 59 0a 0b 20 ?? ?? ?? ?? 06 61 39 ?? ?? ?? ?? 02 7b ?? ?? ?? ?? 02 20 ?? ?? ?? ?? 06 60 0a 02 7b ?? ?? ?? ?? 6f ?? ?? ?? 06 06 20 ?? ?? ?? ?? 58 0a 07}  //weight: 10, accuracy: Low
        $x_1_2 = "pastebin.com/raw/HtP8N00Y" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_ARC_2147905161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.ARC!MTB"
        threat_id = "2147905161"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0a 2b 17 03 06 8f ?? 00 00 01 25 49 02 06 02 8e 69 5d 91 61 d1 53 06 17 58 0a 06 03 8e 69 32 e3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_NB_2147905367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.NB!MTB"
        threat_id = "2147905367"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "urlhaus.abuse.ch/downloads/text_online" ascii //weight: 5
        $x_1_2 = "WebClient" ascii //weight: 1
        $x_1_3 = "DownloadString" ascii //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "New folder" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_ARP_2147908459_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.ARP!MTB"
        threat_id = "2147908459"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "searc.me/66e76889-cdf6-4795-a71c-23238a3b2b51" ascii //weight: 1
        $x_1_2 = "SOFTWARE\\Policies\\Google\\Chrome" ascii //weight: 1
        $x_1_3 = "PromptForPassword" ascii //weight: 1
        $x_1_4 = "INCORRECT_PASSWORD" ascii //weight: 1
        $x_1_5 = "REQUEST_ADMINISTRATOR" ascii //weight: 1
        $x_1_6 = "REQUIRE_SMARTCARD" ascii //weight: 1
        $x_1_7 = "KEEP_USERNAME" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Redcap_NR_2147940057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Redcap.NR!MTB"
        threat_id = "2147940057"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Redcap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8d 09 00 00 01 0a 06 20 00 00 00 00 fe 09 00 00 a2 06 28 ?? 07 00 06 74 10 00 00 01}  //weight: 2, accuracy: Low
        $x_1_2 = "HoffCon.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

