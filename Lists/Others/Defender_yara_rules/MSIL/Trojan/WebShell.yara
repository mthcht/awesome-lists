rule Trojan_MSIL_WebShell_CCGU_2147900872_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.CCGU!MTB"
        threat_id = "2147900872"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 25 16 9a 74 ?? 00 00 01 fe ?? ?? ?? 25 17 9a 74 ?? 00 00 01 fe ?? ?? ?? 25 ?? 9a 17 28 ?? 00 00 0a ?? 26 03}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_HNA_2147907167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.HNA!MTB"
        threat_id = "2147907167"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {59 00 57 00 4e 00 68 00 59 00 32 00 4d 00 77 00 4e 00 57 00 46 00 68 00 5a 00 6d 00 46 00 6d 00 4e 00 67 00 3d 00 3d 00 00 07 67 00 6f 00 76}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_HNE_2147907711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.HNE!MTB"
        threat_id = "2147907711"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 41 70 70 5f 57 65 62 5f}  //weight: 1, accuracy: High
        $x_49_2 = {5f 00 5f 00 52 00 65 00 6e 00 64 00 65 00 72 00 5f 00 5f 00 63 00 6f 00 6e 00 74 00 72 00 6f 00 6c 00 31 00 2e 00 66 00 75 00 6e 00 00}  //weight: 49, accuracy: High
        $x_49_3 = {66 00 75 00 6e 00 00 19 72 00 65 00 74 00 75 00 72 00 6e 00 20 00 76 00 61 00 6c 00 75 00 65 00}  //weight: 49, accuracy: High
        $x_25_4 = {56 73 61 45 6e 67 69 6e 65 00 4d 69 63 72 6f 73 6f 66 74 2e 4a 53 63 72 69 70 74 2e 56 73 61 00 49 6d 70 6f 72 74 00 50 61 63 6b 61 67 65 00 49 4e 65 65 64 45 6e 67 69 6e 65 00 49 52 65 71 75 69 72 65 73 53 65 73 73 69 6f 6e 53 74 61 74 65 00 53 79 73 74 65 6d 2e 57 65 62 2e 53 65 73 73 69 6f 6e 53 74 61 74 65 00 49 48 74 74 70 48 61 6e 64 6c 65 72 00 50 61 67 65 00 53 79 73 74 65 6d}  //weight: 25, accuracy: High
        $x_25_5 = {00 45 76 61 6c 75 61 74 65 50 6c 75 73 00 75 6e 65 73 63 61 70 65 00 4a 53 63 72 69 70 74 45 76 61 6c 75 61 74 65 00 50 6f 70 53 63 72 69 70 74 4f 62 6a 65 63 74 00 41 64 64 57 72 61 70 70 65 64 46 69 6c 65 44 65 70 65 6e 64 65 6e 63 69 65 73 00 67 65 74 5f 52 65 71 75 65 73 74 00 56 61 6c 69 64 61 74 65 49 6e 70 75 74 00 43 72 65 61 74 65 45 6e 67 69 6e 65 57 69 74 68 54 79 70 65 00 41 70 70 5f 57 65 62}  //weight: 25, accuracy: High
        $x_19_6 = {41 64 64 57 72 61 70 70 65 64 46 69 6c 65 44 65 70 65 6e 64 65 6e 63 69 65 73 00 56 61 6c 69 64 61 74 65 49 6e 70 75 74 00 43 72 65 61 74 65 45 6e 67 69 6e 65 57 69 74 68 54 79 70 65 00 41 70 70 5f 57 65 62 5f}  //weight: 19, accuracy: High
        $x_3_7 = {00 4a 53 63 72 69 70 74 45 76 61 6c 75 61 74 65 00}  //weight: 3, accuracy: High
        $x_3_8 = {00 50 6f 70 53 63 72 69 70 74 4f 62 6a 65 63 74 00}  //weight: 3, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_25_*) and 1 of ($x_19_*) and 2 of ($x_3_*))) or
            ((2 of ($x_25_*))) or
            ((1 of ($x_49_*) and 1 of ($x_1_*))) or
            ((1 of ($x_49_*) and 1 of ($x_3_*))) or
            ((1 of ($x_49_*) and 1 of ($x_19_*))) or
            ((1 of ($x_49_*) and 1 of ($x_25_*))) or
            ((2 of ($x_49_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_WebShell_HNC_2147907890_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.HNC!MTB"
        threat_id = "2147907890"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 61 73 74 4f 62 6a 65 63 74 46 61 63 74 6f 72 79 5f 61 70 70 5f 77 65 62 5f [0-48] 5f 5f 41 53 50 00}  //weight: 1, accuracy: Low
        $x_1_2 = {00 09 70 00 61 00 73 00 73 00 00 03 2d 00 01 01 00 0f 70 00 61 00 79 00 6c 00 6f 00 61 00 64 00 00 09 4c 00 6f 00 61 00 64}  //weight: 1, accuracy: High
        $x_1_3 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_HNH_2147908329_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.HNH!MTB"
        threat_id = "2147908329"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "App_Web_" ascii //weight: 1
        $x_1_2 = {00 42 69 6e 61 72 79 52 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 65 73 73 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_10_6 = {12 7d 1d 05 04 20 01 1c 0e 04 20 01}  //weight: 10, accuracy: High
        $x_10_7 = {00 07 63 00 76 00 62 00 00 0f 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_WebShell_HNB_2147911050_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.HNB!MTB"
        threat_id = "2147911050"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "310"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {5f 61 73 70 78 [0-48] 41 53 50}  //weight: 50, accuracy: Low
        $x_50_2 = {46 61 73 74 4f 62 6a 65 63 74 46 61 63 74 6f 72 79 5f 61 70 70 5f 77 65 62 5f [0-48] 5f 5f 41 53 50 00}  //weight: 50, accuracy: Low
        $x_50_3 = {53 79 73 74 65 6d 2e 57 65 62 00 53 79 73 74 65 6d 2e [0-37] 65 62 2e 53 65 73 73 69 6f 6e 53 74 61 74 65 00 49 52 65 71 75 69 72 65 73 53 65 73 73 69 6f 6e 53 74 61 74 65}  //weight: 50, accuracy: Low
        $x_50_4 = {6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74}  //weight: 50, accuracy: High
        $x_50_5 = {43 72 65 61 74 65 5f 41 53 50 5f [0-80] 5f 61 73 ?? 78 00}  //weight: 50, accuracy: Low
        $x_50_6 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 00 47 65 6e 65 72 61 74 65 64 43 6f 64 65 41 74 74 72 69 62 75 74 65 00 53 79 73 74 65 6d}  //weight: 50, accuracy: High
        $x_10_7 = {43 72 79 70 74 6f 67 72 61 70 68 79 00 52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 00 53 79 6d 6d 65 74 72 69 63 41 6c 67 6f 72 69 74 68 6d 00 49 43 72 79 70 74 6f 54 72 61 6e 73 66 6f 72 6d 00 43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b 00 53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 00 41 73 73 65 6d 62 6c 79 00 4c 6f 61 64 00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 00 45 71 75 61 6c 73 00}  //weight: 10, accuracy: High
        $x_10_8 = {00 67 65 74 5f 49 74 65 6d 00 41 73 73 65 6d 62 6c 79 00 4c 6f 61 64 00 43 72 65 61 74 65 49 6e 73 74 61 6e 63 65}  //weight: 10, accuracy: High
        $x_3_9 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 3, accuracy: High
        $x_1_10 = {00 67 65 74 5f 54 6f 74 61 6c 42 79 74 65 73 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 43 6f 6e 76 65 72 74 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 67 65 74 5f 52 65 73 70 6f 6e 73 65 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 48 74 74 70 52 65 73 70 6f 6e 73 65 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 42 69 6e 61 72 79 52 65 61 64 00}  //weight: 1, accuracy: High
        $x_1_15 = {00 52 69 6a 6e 64 61 65 6c 4d 61 6e 61 67 65 64 00}  //weight: 1, accuracy: High
        $x_1_16 = {00 42 69 6e 61 72 79 57 72 69 74 65 00}  //weight: 1, accuracy: High
        $x_10_17 = {00 42 79 74 65 00 43 6f 6e 63 61 74 00 54 6f 49 6e 74 33 32 00 4c 6f 61 64 00 67 65 74 5f 54 6f 74 61 6c 42 79 74 65 73}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_50_*) and 1 of ($x_3_*) and 7 of ($x_1_*))) or
            ((6 of ($x_50_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_WebShell_AQ_2147923791_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.AQ!MTB"
        threat_id = "2147923791"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0a 16 0b 38 ?? 00 00 00 00 02 1d 8d ?? 00 00 01 13 05 11 05 16 72 ?? ?? 00 70 a2 11 05 17 02 06 07 9a 28 ?? 00 00 06 a2 11 05 18 72 ?? ?? 00 70 a2 11 05 19 07 8c ?? 00 00 01 a2 11 05 1a 72 ?? ?? 00 70 a2 11 05 1b 06 07 9a a2 11 05 1c 72 ?? ?? 00 70 a2 11}  //weight: 3, accuracy: Low
        $x_1_2 = "Clear All Thread ...." wide //weight: 1
        $x_1_3 = "8f34b0861bce1e0536a2a3d33c7a0f39" wide //weight: 1
        $x_1_4 = "File time clone success!" wide //weight: 1
        $x_1_5 = "siyuanceshi@163.com" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_ACH_2147944105_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.ACH!MTB"
        threat_id = "2147944105"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0a 02 06 7d ?? 00 00 0a 06 02 6f ?? 00 00 0a 00 06 72 ?? ?? 00 70 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 72 ?? ?? 00 70 6f ?? 00 00 0a 00 06 72 ?? ?? 00 70 6f ?? 00 00 0a 00 06 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {0a 02 06 7d ?? ?? 00 0a 06 02 6f ?? 00 00 0a 00 06 72 ?? ?? 00 70 6f ?? 00 00 0a 00 06 18 6f ?? 00 00 0a 00 06 72 ?? ?? 00 70 6f ?? 00 00 0a 00 06 72 ?? ?? 00 70 6f ?? 00 00 0a 00 06 1f 19 6f ?? 00 00 0a 00 06 0b 2b 00 07 2a}  //weight: 2, accuracy: Low
        $x_1_3 = "hidBaoBiao" wide //weight: 1
        $x_1_4 = "txtPassWord" wide //weight: 1
        $x_1_5 = "d4539315521e0e79" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_WebShell_GVB_2147945398_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.GVB!MTB"
        threat_id = "2147945398"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {28 0f 00 00 06 2c 14 7e 02 00 00 04 72 15 00 00 70 28 2f 00 00 0a 80 02 00 00 04 06 72 1d 00 00 70 7e 02 00 00 04 28 2f 00 00 0a 7d 18 00 00 04 06 fe 06 48 00 00 06 73 30 00 00 0a 28 31 00 00 0a 6f 32 00 00 0a 2a}  //weight: 5, accuracy: High
        $x_2_2 = "powershell" wide //weight: 2
        $x_2_3 = "RunAs" wide //weight: 2
        $x_1_4 = "/restart" wide //weight: 1
        $x_1_5 = "/suicide" wide //weight: 1
        $x_1_6 = "/startup" wide //weight: 1
        $x_1_7 = "/delstartup" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_WebShell_AUAB_2147947492_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.AUAB!MTB"
        threat_id = "2147947492"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {01 25 16 72 97 03 00 70 d0 ?? 00 00 01 16 73 ?? 00 00 0a a2 25 17 72 9f 03 00 70 d0 ?? 00 00 01 17 73 ?? 00 00 0a a2 25 18 72 c5 03 00 70 d0 ?? 00 00 01 18 73 ?? 00 00 0a a2 25 19 72 d7 03 00 70 d0 ?? 00 00 01 19 73 ?? 00 00 0a a2 02}  //weight: 4, accuracy: Low
        $x_2_2 = {06 02 72 69 03 00 70 28 ?? 00 00 0a 7e ?? 00 00 04 16 40 ?? 00 00 00 17 8d ?? 00 00 01 0a 06 16 72 69 03 00 70 a2 02 06 28 ?? 00 00 0a 80 ?? 00 00 04 17 80 ?? 00 00 04 02 28 ?? 00 00 0a 20 80 c3 c9 01 28 ?? 00 00 0a 2a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_MR_2147947656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.MR!MTB"
        threat_id = "2147947656"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {08 09 94 0a 00 06 03 fe 01 16 fe 01 13 04 11 04 2d 04 17 0b de 15 00 09 17 58 0d}  //weight: 5, accuracy: High
        $x_10_2 = {0a 06 16 1b 9e 06 17 17 9e 06 18 1a 9e 06}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_AHBB_2147948009_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.AHBB!MTB"
        threat_id = "2147948009"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {16 fe 01 13 07 11 07 2d 0c 7e ?? 00 00 0a 13 06 38 8e 00 00 00 28 ?? ?? 00 0a 72 ?? ?? 00 70 1e 1f 30 6f ?? ?? 00 0a 16 1e 6f ?? ?? 00 0a 6f ?? ?? 00 0a 0a 28 ?? ?? 00 0a 72 ?? ?? 00 70 1e 1f 30 6f ?? ?? 00 0a 16 1e 6f ?? ?? 00 0a 6f ?? ?? 00 0a 0b 03 28 ?? ?? 00 0a 0c 73 ?? ?? 00 0a 0d 73 ?? ?? 00 0a 13 04 11 04 09 06 07 6f ?? ?? 00 0a 17 73 ?? ?? 00 0a 13 05 11 05 08 16 08 8e 69 6f ?? ?? 00 0a 00 11 05 6f ?? ?? 00 0a 00 28 ?? ?? 00 0a 11 04 6f ?? ?? 00 0a 6f ?? ?? 00 0a 13 06 2b 00 11 06 2a}  //weight: 5, accuracy: Low
        $x_2_2 = {16 fe 01 13 06 11 06 2d 0d 00 7e ?? 00 00 0a 13 05 38 c6 00 00 00 03 2d 1c 02 28 ?? ?? 00 0a 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? ?? 00 0a 28 ?? ?? 00 0a 2b 0b 28 ?? ?? 00 0a 02 6f ?? ?? 00 0a 00 0a 14 0b 73 ?? ?? 00 0a 0c 00 73 ?? ?? 00 0a 0d 09 03 2d 12 08 7e ?? 00 00 04 7e ?? 00 00 04 6f ?? ?? 00 0a 2b 10 08 7e ?? 00 00 04 7e ?? 00 00 04 6f ?? ?? 00 0a 00 17 73 ?? ?? 00 0a 13 04 11 04 06 16 06 8e 69 6f ?? ?? 00 0a 00 11 04 6f ?? ?? 00 0a 00 09 6f ?? ?? 00 0a 0b 00 de 12}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_AQBB_2147948385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.AQBB!MTB"
        threat_id = "2147948385"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 07 06 28 ?? ?? 00 0a 6f ?? ?? 00 0a 28 ?? ?? 00 0a 28 ?? ?? 00 0a 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? ?? 00 0a 0c 02 6f ?? ?? 00 0a 6f ?? ?? 00 0a 07 6f ?? ?? 00 0a 28 ?? ?? 00 0a 0d 73 ?? ?? 00 0a 28 ?? ?? 00 0a 06 6f ?? ?? 00 0a 28 ?? ?? 00 0a 06 6f ?? ?? 00 0a 6f ?? ?? 00 0a 09 16 09 8e 69 6f ?? ?? 00 0a 0d 02 6f ?? ?? 00 0a 6f ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 14 fe 01 16 fe 01 13 07 11 07 2d 63 00 02 6f ?? ?? 00 0a 6f ?? ?? 00 0a 72 ?? ?? 00 70 d0 ?? 00 00 01 28 ?? ?? 00 0a 72 ?? ?? 00 70 17 8d ?? 00 00 01 13 08 11 08 16 d0 ?? 00 00 1b 28 ?? ?? 00 0a a2 11 08 28 ?? ?? 00 0a 14 17 8d ?? 00 00 01 13 09 11 09 16 09 a2 11 09}  //weight: 5, accuracy: Low
        $x_2_2 = {0a 13 04 02 6f ?? ?? 00 0a 6f ?? ?? 00 0a 72 ?? ?? 00 70 6f ?? ?? 00 0a 74 ?? 00 00 01 72 ?? ?? 00 70 6f ?? ?? 00 0a 13 05 11 05 11 04 6f ?? ?? 00 0a 26 11 05 09 6f ?? ?? 00 0a 26 11 05 6f ?? ?? 00 0a 26 11 04 6f ?? ?? 00 0a 13 06}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_MKV_2147948847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.MKV!MTB"
        threat_id = "2147948847"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {d0 16 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 72 67 01 00 70 6f ?? 00 00 0a 0a 06 14 28 ?? 00 00 0a 0d 09 2c 0d 00 72 a3 01 00 70 13 04 38 38 01 00 00 06 72 0f 02 00 70 6f ?? 00 00 0a 0b 07 14 28 ?? 00 00 0a 13 05 11 05 2c 0d}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_AOCB_2147949203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.AOCB!MTB"
        threat_id = "2147949203"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 72 ?? 00 00 70 1f 28 6f ?? 00 00 0a 0c 08 14 16 8d ?? 00 00 01 6f ?? 00 00 0a 74 ?? 00 00 01 0d 02 28 ?? 00 00 0a 1f 09 8d ?? 00 00 01 13 04 11 04 16 09 6f ?? 00 00 0a a2 11 04 17 72 ?? ?? 00 70 a2 11 04 18 09 6f ?? 00 00 0a 8c ?? 00 00 01 a2 11 04 19 72 ?? ?? 00 70 a2 11 04 1a 09 6f ?? 00 00 0a a2 11 04 1b 72 ?? ?? 00 70 a2 11 04 1c 09 6f ?? 00 00 0a a2 11 04 1d 72 ?? ?? 00 70 a2 11 04 1e 09 6f ?? 00 00 0a 8c ?? 00 00 01 a2 11 04 28 ?? 00 00 0a 6f ?? 00 00 0a 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_MZB_2147950310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.MZB!MTB"
        threat_id = "2147950310"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {02 72 81 74 00 70 28 ?? 00 00 0a 00 7e 18 00 00 04 0b 07 2d 2e 00 02 28 ?? 00 00 0a 80 19 00 00 04 17 8d 4a 00 00 01 0a 06 16 72 81 74 00 70 a2 02 06 28 ?? 00 00 0a 80 1a 00 00 04 17 80 18 00 00 04 00 02 28 ?? 00 00 0a 20 80 c3 c9 01 6f ?? 00 00 0a 00 00 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_AXDB_2147950638_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.AXDB!MTB"
        threat_id = "2147950638"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 07 06 28 ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 72 ?? 00 00 70 6f ?? 00 00 0a 0c 02 6f ?? 00 00 0a 6f ?? 00 00 0a 07 6f ?? 00 00 0a 28 ?? 00 00 0a 0d 73 ?? 00 00 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 09 16 09 8e 69 6f ?? 00 00 0a 0d 02 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 2d 60}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_AHEB_2147951198_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.AHEB!MTB"
        threat_id = "2147951198"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 16 02 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 02 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 14 fe 01 16 fe 01 13 05 11 05 2d 63 00 02 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? ?? 00 70 d0 ?? 00 00 01 28 ?? 00 00 0a 72 ?? ?? 00 70 17 8d ?? 00 00 01 13 06 11 06 16 d0 ?? 00 00 1b 28 ?? 00 00 0a a2 11 06 28 ?? 00 00 0a 14 17 8d ?? 00 00 01 13 07 11 07 16 07 a2 11 07}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_CB_2147951249_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.CB!MTB"
        threat_id = "2147951249"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {41 70 70 5f 57 65 62 5f [0-15] 2e 64 6c 6c}  //weight: 2, accuracy: Low
        $x_2_2 = "Factory_app_web_" ascii //weight: 2
        $x_2_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 2e 00 4e 00 45 00 54 00 5c 00 46 00 72 00 61 00 6d 00 65 00 77 00 6f 00 72 00 6b}  //weight: 2, accuracy: High
        $x_5_4 = {63 00 6d 00 64 00 00 09 70 00 6f 00 73 00 74}  //weight: 5, accuracy: High
        $x_5_5 = {77 00 65 00 62 00 73 00 68 00 65 00 6c 00 6c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_FPP_2147951551_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.FPP!MTB"
        threat_id = "2147951551"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {13 04 00 02 28 ?? 00 00 0a 72 52 05 00 70 28 ?? 00 00 0a 00 0a 00 02 28 ?? 00 00 0a 72 60 05 00 70 28 ?? 00 00 0a 00 0b 06 39 11 01 00 00 06 72 6e 05 00 70 28 ?? 00 00 0a 3a 01 01 00 00 00 00 28 2a 00 00 0a 00 23 00 00 00 00 00 6a f8 40 5a 28 ?? 00 00 0a 28 ?? 00 00 0a 00 72 70 05 00 70 28 ?? 00 00 0a 0c 07 7e 2e 00 00 0a 28 ?? 00 00 0a 3a 4d 00 00 00 11 05 07 72 6e 05 00 70 28 ?? 00 00 0a 3a 3b 00 00 00}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_CC_2147952052_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.CC!MTB"
        threat_id = "2147952052"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {70 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 6f ?? 00 00 0a 0b 28 ?? 00 00 0a 06 6f ?? 00 00 0a 0c 73 ?? 00 00 0a 08 08 6f ?? 00 00 0a 07 16 02}  //weight: 3, accuracy: Low
        $x_1_2 = "App_Web_" ascii //weight: 1
        $x_1_3 = "RijndaelManaged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_AXEB_2147952084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.AXEB!MTB"
        threat_id = "2147952084"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 0b 07 18 6f ?? 00 00 0a 00 07 28 ?? 00 00 0a 06 6f ?? 00 00 0a 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 03 16 03 8e 69 6f ?? 00 00 0a 0c 2b 00 08 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_WebShell_KRI_2147952184_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/WebShell.KRI!MTB"
        threat_id = "2147952184"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "WebShell"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 16 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 73 17 00 00 0a 28 ?? 00 00 0a 72 93 00 00 70 6f ?? 00 00 0a 28 ?? 00 00 0a 72 93 00 00 70 6f ?? 00 00 0a 6f ?? 00 00 0a 11 04 16 11 04 8e 69 6f ?? 00 00 0a 28 ?? 00 00 0a 6f ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 06 1f 10 6f ?? 00 00 0a 6f ?? 00 00 0a de 03}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

