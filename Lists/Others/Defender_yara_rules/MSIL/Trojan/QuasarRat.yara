rule Trojan_MSIL_QuasarRat_NE_2147828113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NE!MTB"
        threat_id = "2147828113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "~Kirkuk1#~" wide //weight: 1
        $x_1_2 = "c2NvcmxpYgBTeXN0ZW0uQ29sbGVjdGlvbnMuR2V" wide //weight: 1
        $x_1_3 = "jAGgAZQBjAGsAZQBkAEwAaQBzAHQAQgBvAHgAMgAADW" wide //weight: 1
        $x_1_4 = "QAYQByAEwAaQBiAFgALgBkAGwAbAAA" wide //weight: 1
        $x_1_5 = "3NpbmcAU3lzdGVtLkRyY" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEA_2147828114_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEA!MTB"
        threat_id = "2147828114"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 0f 00 00 06 0b 07 16 07 8e 69 28 23 00 00 0a 00 07 0c 2b 00 08 2a}  //weight: 1, accuracy: High
        $x_1_2 = "Lozpuucdpe" wide //weight: 1
        $x_1_3 = "Elhoxxzfpgfytg" wide //weight: 1
        $x_1_4 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEC_2147833833_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEC!MTB"
        threat_id = "2147833833"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ccsqs.exe" ascii //weight: 3
        $x_3_2 = "EvX.Common.DNS" ascii //weight: 3
        $x_3_3 = "BetterCall.Models" ascii //weight: 3
        $x_3_4 = "Ban Solutions 2022" ascii //weight: 3
        $x_3_5 = "get_updateBat" ascii //weight: 3
        $x_3_6 = "ReverseProxyDisconnect" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAA_2147836088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAA!MTB"
        threat_id = "2147836088"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 00 06 04 28 09 00 00 2b 7d aa 00 00 04 03 06 fe 06 80 01 00 06 73 f1 00 00 0a 28 0a 00 00 2b 28 09 00 00 2b 0b}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAB_2147837074_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAB!MTB"
        threat_id = "2147837074"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {a2 25 18 09 a2 25 19 17 8c ?? 00 00 01 a2 13 04 14 13 05 07 28 ?? 00 00 0a}  //weight: 5, accuracy: Low
        $x_5_2 = "aHR0cHM6Ly9vbmUubGl0ZXNoYXJlLmNvL2Rvd25sb2FkLnBocD9pZD0zSjhZNTAy" wide //weight: 5
        $x_2_3 = "C:\\Windows\\Microsoft.NET\\Framework\\v4.0.30319" wide //weight: 2
        $x_2_4 = "targetallah" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAD_2147840579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAD!MTB"
        threat_id = "2147840579"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Tiotcjlt.exe" wide //weight: 5
        $x_2_2 = "ezB9IFVuZXhwZWN0ZWQgRXJyb3I=" ascii //weight: 2
        $x_2_3 = "RW5hYmxlVmlzdWFsU3R5bGVz" ascii //weight: 2
        $x_1_4 = "SmartAssembly.HouseOfCards" ascii //weight: 1
        $x_1_5 = "GetExecutingAssembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAG_2147841520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAG!MTB"
        threat_id = "2147841520"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 06 17 6f 2a 00 00 0a 06 18 6f 2b 00 00 0a 06 03 04 6f 2c 00 00 0a 0b 07 02 16 02 8e 69 6f 2d 00 00 0a 0c 07 6f 2e 00 00 0a 06 6f 2f 00 00 0a 08 2a}  //weight: 10, accuracy: High
        $x_2_2 = "amsi.dll" wide //weight: 2
        $x_2_3 = "set_CreateNoWindow" ascii //weight: 2
        $x_2_4 = "payload.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_CNU_2147842146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.CNU!MTB"
        threat_id = "2147842146"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i9LxRGdN/ZnwPcvru4LmAGBrTitY5YY9km9Brq6HAQY=" wide //weight: 1
        $x_1_2 = "SPmN84gT2WeV+ZIDsvzzpw==" wide //weight: 1
        $x_1_3 = "Gb9NBEPqu/m7lczaCRQ3NQ==" wide //weight: 1
        $x_1_4 = "oXMj+yyKbVuy/O9rZvEt9A==" wide //weight: 1
        $x_1_5 = "uJGwOaQPgcrxM36UoyBizQ==" wide //weight: 1
        $x_1_6 = "GetString" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAH_2147842280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAH!MTB"
        threat_id = "2147842280"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {0a 16 0b 2b 18 06 02 07 1e 6f 1f 00 00 0a 18 28 20 00 00 0a 6f 21 00 00 0a 07 1e 58 0b 07 02 6f 22 00 00 0a 32 df}  //weight: 10, accuracy: High
        $x_2_2 = "CT_VooDoo" ascii //weight: 2
        $x_2_3 = "Decrypt" ascii //weight: 2
        $x_2_4 = "GetExecutingAssembly" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAJ_2147842564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAJ!MTB"
        threat_id = "2147842564"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "306251e5-9074-4ce3-be07-f3d56dab4ca3" ascii //weight: 5
        $x_1_2 = "get_DWS23" ascii //weight: 1
        $x_1_3 = "WinFormsApp1" ascii //weight: 1
        $x_1_4 = "DebuggerHiddenAttribute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAK_2147843186_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAK!MTB"
        threat_id = "2147843186"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {38 32 00 00 00 28 06 00 00 0a 11 00 6f 07 00 00 0a 28 08 00 00 0a 13 03}  //weight: 10, accuracy: High
        $x_5_2 = "Recrypted" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAM_2147843444_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAM!MTB"
        threat_id = "2147843444"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "eaae8b8b-a56e-4f77-85da-02b7b00aa56a" ascii //weight: 5
        $x_2_2 = "LogicGames.Properties.Resources" wide //weight: 2
        $x_2_3 = "SoundPlayer" ascii //weight: 2
        $x_1_4 = "$$method0x6000317-1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAN_2147843627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAN!MTB"
        threat_id = "2147843627"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "4030fe67-8ade-40ec-90ff-c569a3c046b2" ascii //weight: 5
        $x_2_2 = "vbs.exe" ascii //weight: 2
        $x_2_3 = "WScript.Shell" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NEAP_2147844433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NEAP!MTB"
        threat_id = "2147844433"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "df3114c3-43e3-4b44-b51f-89ccbf247c76" ascii //weight: 5
        $x_2_2 = "SAITMCalculator.exe" ascii //weight: 2
        $x_2_3 = "by BLD Dilanga" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_RPY_2147845896_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.RPY!MTB"
        threat_id = "2147845896"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 08 02 8e 69 5d ?? ?? ?? ?? ?? 02 08 02 8e 69 5d 91 07 08 07 8e 69 5d 91 61 ?? ?? ?? ?? ?? 02 08 18 58 17 59 02 8e 69 5d 91 59 20 ff 00 00 00 58 19 58 18 59 20 00 01 00 00 5d d2 9c 08 17 58 1a 2d 38 26 08 6a 02 8e 69 17 59 6a 06 17 58 6e 5a 31 ad}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_RPZ_2147848113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.RPZ!MTB"
        threat_id = "2147848113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Quasar Client" wide //weight: 1
        $x_1_2 = "schtasks" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "FileZilla\\recentservers.xml" wide //weight: 1
        $x_1_5 = "BraveSoftware\\Brave-Browser" wide //weight: 1
        $x_1_6 = "PK11SDR_Decrypt" wide //weight: 1
        $x_1_7 = "Mozilla/5.0" wide //weight: 1
        $x_1_8 = "del /a /q /f" wide //weight: 1
        $x_1_9 = "FROM AntivirusProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NN_2147901470_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NN!MTB"
        threat_id = "2147901470"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 13 0f 26 16 13 0a 38 2f ?? ?? ?? 11 04 11 0a 8f 47 ?? ?? ?? 25 71 47 ?? ?? ?? 11 08 11 09 5a 11 0c 58 ?? ?? ?? ?? ?? ?? ?? ?? ?? 33 61 5e d2 61 d2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_LL_2147902546_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.LL!MTB"
        threat_id = "2147902546"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 13 0a 26 11 07 11 07 8e 69 1c 59 91 ?? ?? ?? ?? 8e 69 1b 59 91 1e 62 60 11 07 11 07 8e 69 19 59 91}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_NA_2147904791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.NA!MTB"
        threat_id = "2147904791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {93 61 1f 61 5f 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_AMAI_2147914692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.AMAI!MTB"
        threat_id = "2147914692"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 09 06 09 91 11 ?? 61 20 00 01 00 00 5d d2 9c 06 09 06 09 91}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_AMAC_2147925923_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.AMAC!MTB"
        threat_id = "2147925923"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {0a 00 11 05 11 04 1f 10 6f ?? ?? 00 0a 6f ?? ?? 00 0a 00 11 05 11 05 6f ?? ?? 00 0a 11 05 6f ?? ?? 00 0a 6f ?? ?? 00 0a 13 06 11 06 02 74 ?? 00 00 1b 16 02 14 72 ?? ?? ?? 70 16}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_SCW_2147937380_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.SCW!MTB"
        threat_id = "2147937380"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 18 00 00 04 28 f5 04 00 06 80 18 00 00 04 7e 08 00 00 04 28 f5 04 00 06 80 08 00 00 04 7e 09 00 00 04 28 f5 04 00 06 80 09 00 00 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_SIPM_2147939381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.SIPM!MTB"
        threat_id = "2147939381"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {0a 72 86 e5 84 70 28 03 00 00 0a 0b 72 e0 e5 84 70 28 03 00 00 0a 0c 28 04 00 00 0a 0d 09 07 6f 05 00 00 0a 09}  //weight: 2, accuracy: High
        $x_2_2 = {11 06 06 16 06 8e 69 6f 0b 00 00 0a 11 06 6f 0c 00 00 0a 11 05 6f 0d 00 00 0a 28 0e 00 00 0a 6f 0f 00 00 0a 14 14 6f 10 00 00 0a}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_SEBA_2147939383_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.SEBA!MTB"
        threat_id = "2147939383"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 0b 00 00 04 0c 08 0b 07 1f 29 2e 12 2b 00 07 1f 2a 2e 02 2b 12 1f 26 80 0b 00 00 04 2b 09 1f 25 80 0b 00 00 04 2b 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_SLUY_2147944193_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.SLUY!MTB"
        threat_id = "2147944193"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {da 0d 16 13 04 2b 4d 07 11 04 91 08 1b 20 88 13 00 00 6f e1 00 00 0a d8 28 92 00 00 0a 16 fe 01 13 05 11 05}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_QuasarRat_KAT_2147946240_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/QuasarRat.KAT!MTB"
        threat_id = "2147946240"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "QuasarRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {28 2e 01 00 0a 13 09 11 09 06 6f 2f 01 00 0a 6f 30 01 00 0a 00 11 09 06 6f 2f 01 00 0a 6f 31 01 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

