rule Trojan_MSIL_Starter_F_2147690661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.F"
        threat_id = "2147690661"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 65 4c 6f 6f 6b 75 70 53 76 69 2e 65 78 65 [0-8] 41 65 4c 6f 6f 6b 75 70 53 76 69}  //weight: 1, accuracy: Low
        $x_1_2 = {41 00 70 00 70 00 6c 00 69 00 63 00 61 00 74 00 69 00 6f 00 6e 00 20 00 45 00 78 00 70 00 65 00 72 00 69 00 65 00 6e 00 63 00 65 00 [0-2] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 52 00 75 00 6e 00 [0-2] 50 00 72 00 6f 00 66 00 53 00 76 00 63 00 [0-2] 25 00 41 00 70 00 70 00 44 00 61 00 74 00 61 00 25 00 [0-2] 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 50 00 72 00 6f 00 66 00 53 00 76 00 63 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {7b 00 34 00 37 00 30 00 65 00 32 00 33 00 31 00 64 00 2d 00 39 00 31 00 39 00 31 00 2d 00 34 00 39 00 65 00 34 00 2d 00 38 00 31 00 35 00 34 00 2d 00 36 00 38 00 30 00 61 00 31 00 38 00 32 00 35 00 66 00 63 00 66 00 38 00 7d 00 [0-2] 53 00 65 00 74 00 56 00 61 00 6c 00 75 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_PA_2147742834_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.PA!MTB"
        threat_id = "2147742834"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Temp\\USB3MON.exe" wide //weight: 1
        $x_1_2 = "\\Temp\\found.000" wide //weight: 1
        $x_1_3 = "found.000.exe" ascii //weight: 1
        $x_1_4 = "zawrHJf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_J_2147743689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.J!ibt"
        threat_id = "2147743689"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 1d 00 00 0a 72 01 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00 28 1d 00 00 0a 72 ?? 00 00 70 28 1e 00 00 0a 28 1f 00 00 0a 26 de 0c 28 20 00 00 0a 28 21 00 00 0a de 00}  //weight: 1, accuracy: Low
        $x_1_2 = "get_StartupPath" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_MS_2147744917_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.MS!MTB"
        threat_id = "2147744917"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 0b 11 0b a2 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6f ?? ?? ?? ?? 13 0c 11 0c 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 13 0d 11 0d 72 ?? ?? ?? ?? 6f ?? ?? ?? ?? 13 0e 73 ?? ?? ?? ?? 13 0f 11 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_AT_2147779310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.AT!MTB"
        threat_id = "2147779310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0b de 0a 07 2c 06 07 6f ?? ?? ?? 0a dc 73 05 00 00 0a 0a 06 6f ?? ?? ?? 0a 72 ?? ?? ?? 70 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 26 de 03 26 de 00 1f 64 28 ?? ?? ?? 0a 2b a8}  //weight: 10, accuracy: Low
        $x_4_2 = "\\AppData\\Roaming\\LolClient\\" ascii //weight: 4
        $x_3_3 = "get_ExecutablePath" ascii //weight: 3
        $x_3_4 = "ProcessStartInfo" ascii //weight: 3
        $x_3_5 = "set_FileName" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_3_*))) or
            ((1 of ($x_10_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Starter_EDV_2147783113_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.EDV!MTB"
        threat_id = "2147783113"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "\\$LimeUSB\\" ascii //weight: 3
        $x_3_2 = "%USB%" ascii //weight: 3
        $x_3_3 = "LimeUSB\\Payload.vbs" ascii //weight: 3
        $x_3_4 = "System.Reflection" ascii //weight: 3
        $x_3_5 = "AssemblyTrademarkAttribute" ascii //weight: 3
        $x_3_6 = "GuidAttribute" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_EB_2147786313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.EB!MTB"
        threat_id = "2147786313"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {fa 25 33 00 16 00 00 01 00 00 00 06 00 00 00 02 00 00 00 01 00 00 00 05 00 00 00 04 00 00 00 01 00 00 00 02}  //weight: 10, accuracy: High
        $x_3_2 = "E:\\$LimeUSB\\foto" ascii //weight: 3
        $x_3_3 = "E:\\$LimeUSB\\LimeUSB.exe" ascii //weight: 3
        $x_3_4 = "Trademark - Lime" ascii //weight: 3
        $x_3_5 = "System.Diagnostics" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_AH_2147787513_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.AH!MTB"
        threat_id = "2147787513"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {28 1d 00 00 0a 28 1e 00 00 0a 0c 08 08 6f 1f 00 00 0a 17 da 28 20 00 00 0a 72 01 00 00 70 28 21 00 00 0a 0a 1d 28 22 00 00 0a 72 0b 00 00 70 06 28 23 00 00 0a 0b 07 28 24 00 00 0a 2d 31}  //weight: 10, accuracy: High
        $x_3_2 = "GetFileNameWithoutExtension" ascii //weight: 3
        $x_3_3 = "get_ExecutablePath" ascii //weight: 3
        $x_3_4 = "GetFolderPath" ascii //weight: 3
        $x_3_5 = "get_Length" ascii //weight: 3
        $x_3_6 = "get_FileSystem" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_EAA_2147797361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.EAA!MTB"
        threat_id = "2147797361"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$LimeUSB\\DONE\\Expenses sheet.xlsx" ascii //weight: 1
        $x_1_2 = "$LimeUSB\\LimeUSB.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_KAA_2147895798_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.KAA!MTB"
        threat_id = "2147895798"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/hostdl.exe" wide //weight: 1
        $x_1_2 = "GetProcessesByName" ascii //weight: 1
        $x_1_3 = "UseShellExecute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_HNS_2147906371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.HNS!MTB"
        threat_id = "2147906371"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {73 04 00 00 06 0a 06 02 7d 02 00 00 04 06 fe 06 05 00 00 06 73 09 00 00 0a 73 0a 00 00 0a 28 0b 00 00 0a 7e 01 00 00 04 2d 11 14 fe 06 03 00 00 06 73 09 00 00 0a 80 01 00 00 04 7e 01 00 00 04 73 0a 00 00 0a 28 0b 00 00 0a 2a 1e 02 28 04 00 00 0a 2a}  //weight: 2, accuracy: High
        $x_2_2 = {53 74 72 69 6e 67 00 4a 6f 69 6e 00 53 79 73 74 65 6d 2e 44 69 61 67 6e 6f 73 74 69 63 73 00 50 72 6f 63 65 73 73 00 53 74 61 72 74 00 54 68 72 65 61 64}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_HNA_2147908023_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.HNA!MTB"
        threat_id = "2147908023"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {28 1d 00 00 0a 72 ?? 00 00 70 28 ?? 00 00 0a 28}  //weight: 50, accuracy: Low
        $x_10_2 = {5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 49 00 4d 00 45 00 47 [0-8] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_3 = {2f 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 55 00 53 00 42 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 65 00 78 00 65 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {29 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 77 00 69 00 6e 00 64 00 6f 00 77 00 73 00 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: High
        $x_10_5 = {65 00 63 00 68 00 6f 00 20 00 73 00 68 00 65 00 6c 00 6c 00 3d 00 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 20 00 25 00 62 00 25 00 2e 00 62 00 61 00 74 00 20 00 3e 00 3e 00 20 00 25 00 77 00 69 00 6e 00 64 00 69 00 72 00 25 00 5c 00 73 00 79 00 73 00 74 00 65 00 6d 00 2e 00 69 00 6e 00 69}  //weight: 10, accuracy: High
        $x_5_6 = {5c 00 63 00 6d 00 64 00 2e 00 62 00 61 00 74 00 00 01 00 21 44 00 45 00 4c 00 20 00 2f 00 46 00 20 00 2f 00 53 00 20 00 2f 00 51 00 20 00 2f 00 41}  //weight: 5, accuracy: High
        $x_5_7 = {13 40 00 52 00 65 00 67 00 20 00 41 00 64 00 64 00 20 00 00 15 25 00 48 00 69 00 76 00 65 00 42 00 53 00 4f 00 44 00 25}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*) and 2 of ($x_5_*))) or
            ((1 of ($x_50_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Starter_ASR_2147922602_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.ASR!MTB"
        threat_id = "2147922602"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 01 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 de 0c 28 ?? 00 00 0a 28 ?? 00 00 0a de 00 28 ?? 00 00 0a 72 43 00 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a 26 de 0c}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Starter_MBWO_2147930126_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.MBWO!MTB"
        threat_id = "2147930126"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_20_1 = {67 65 74 5f 53 74 61 72 74 75 70 50 61 74 68 00 53 74 72 69 6e 67 00 43 6f 6e 63 61 74 00 50 72 6f 63 65 73 73 00 53 74 61 72 74}  //weight: 20, accuracy: High
        $x_1_2 = "UHWOVeeg" ascii //weight: 1
        $x_1_3 = "kRCRJy" ascii //weight: 1
        $x_1_4 = "lnFwUn" ascii //weight: 1
        $x_1_5 = "OjtnxDp" ascii //weight: 1
        $x_1_6 = "WKuSAtYBx" ascii //weight: 1
        $x_1_7 = "sGgZHxu" ascii //weight: 1
        $x_1_8 = "TfhaR" ascii //weight: 1
        $x_1_9 = "TawrHJfW" ascii //weight: 1
        $x_1_10 = "dHDMFLR" ascii //weight: 1
        $x_1_11 = "dldGoFYEKg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_20_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Starter_ARR_2147960744_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Starter.ARR!MTB"
        threat_id = "2147960744"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Starter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_8_1 = {0b 14 0c 06 08 25 2d 04 26 09 2b 0a}  //weight: 8, accuracy: High
        $x_12_2 = "TabTipProxy.exe" ascii //weight: 12
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

