rule Trojan_Win32_Rekilc_A_2147705717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rekilc.A"
        threat_id = "2147705717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rekilc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "svho854" ascii //weight: 2
        $x_1_2 = "Install Your Software" wide //weight: 1
        $x_1_3 = "wait shortly while installing" wide //weight: 1
        $x_1_4 = "offers accepted" wide //weight: 1
        $x_1_5 = "Media Player Extreme installation is complete." wide //weight: 1
        $x_1_6 = "Internet Explorer_Server" wide //weight: 1
        $x_1_7 = "C:\\Dropbox\\01\\Coding New Bots\\AmoClick" ascii //weight: 1
        $x_1_8 = "buturuga" ascii //weight: 1
        $x_1_9 = "A Space Screcret Program" wide //weight: 1
        $x_1_10 = "\\Stuuf\\RevRecode\\AmoHybrid\\" ascii //weight: 1
        $x_1_11 = "trol1 Protez" ascii //weight: 1
        $x_2_12 = {c7 45 cc 20 c5 6f 62 66 c7 45 d0 1e a4 66 c7 45 d2 cf 11 ff d6 b9 31 00 00 00}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rekilc_B_2147710060_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rekilc.B"
        threat_id = "2147710060"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rekilc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {44 72 6f 72 6d 75 6e 64 00}  //weight: 5, accuracy: High
        $x_5_2 = {64 78 64 69 61 67 00 58 62 6f 53 00 00 58 62 6f 53}  //weight: 5, accuracy: High
        $x_3_3 = {6d 73 63 6f 6e 66 69 67 00 57 6f 72 6b 53 72 6f 75 73 53}  //weight: 3, accuracy: High
        $x_3_4 = {53 00 74 00 72 00 69 00 6e 00 67 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 [0-16] 30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00}  //weight: 3, accuracy: Low
        $x_1_5 = {46 6f 72 6d 31 ?? ?? ?? ?? ?? 46 6f 72 6d 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 46 6f 72 6d 31 00 35}  //weight: 1, accuracy: Low
        $x_1_6 = {54 69 6d 65 72 32 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 54 69 6d 65 72 31}  //weight: 1, accuracy: Low
        $x_1_7 = {43 6f 6d 6d 61 6e 64 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 44 42 ?? ?? ?? 54 61 68 6f 6d 61}  //weight: 1, accuracy: Low
        $x_1_8 = {46 69 6e 64 57 69 6e 64 6f 77 41 00}  //weight: 1, accuracy: High
        $x_1_9 = {53 68 6f 77 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
        $x_1_10 = "WM_HTML_GETOBJECT" wide //weight: 1
        $x_1_11 = "Internet Explorer_Server" wide //weight: 1
        $x_1_12 = {62 00 74 00 6e 00 4e 00 65 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $n_100_13 = {43 00 72 00 61 00 66 00 74 00 79 00 21 00 [0-32] 50 00 6c 00 61 00 79 00 20 00 41 00 67 00 61 00 69 00 6e 00}  //weight: -100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            ((1 of ($x_5_*) and 1 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_3_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rekilc_C_2147719692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rekilc.C"
        threat_id = "2147719692"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rekilc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {64 78 64 69 61 67 00}  //weight: 2, accuracy: High
        $x_2_2 = {6d 73 63 6f 6e 66 69 67 00}  //weight: 2, accuracy: High
        $x_2_3 = {43 6f 4d 75 72 44 00}  //weight: 2, accuracy: High
        $x_3_4 = {64 78 64 69 61 64 64 64 67 00}  //weight: 3, accuracy: High
        $x_2_5 = {50 65 72 66 6f 72 6d 61 6e 63 65 58 00}  //weight: 2, accuracy: High
        $x_2_6 = {66 69 6e 64 70 72 6f 63 63 65 73 73 00}  //weight: 2, accuracy: High
        $x_2_7 = "Buttonactive" ascii //weight: 2
        $x_3_8 = "BoLEt.UserControl" ascii //weight: 3
        $x_3_9 = {43 61 73 61 42 6f 6e 69 74 61 53 00}  //weight: 3, accuracy: High
        $x_3_10 = "Ficus.UserControl" ascii //weight: 3
        $x_1_11 = {62 00 74 00 6e 00 4e 00 65 00 78 00 74 00 00 00}  //weight: 1, accuracy: High
        $x_1_12 = {69 00 64 00 3d 00 62 00 74 00 6e 00 00 00}  //weight: 1, accuracy: High
        $x_2_13 = {46 6f 72 6d 31 ?? ?? ?? ?? ?? 46 6f 72 6d 31 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 46 6f 72 6d 31 00 35}  //weight: 2, accuracy: Low
        $x_3_14 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 64 00 [0-48] 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 70 00 61 00 74 00 68 00}  //weight: 3, accuracy: Low
        $x_3_15 = {50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 64 00 [0-48] 6e 00 65 00 78 00 74 00}  //weight: 3, accuracy: Low
        $x_3_16 = {43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 [0-16] 4d 00 65 00 64 00 69 00 61 00 50 00 6c 00 61 00 79 00 65 00 72 00 [0-32] 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 49 00 64 00}  //weight: 3, accuracy: Low
        $x_3_17 = {6e 00 65 00 78 00 74 00 [0-16] 53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00}  //weight: 3, accuracy: Low
        $x_3_18 = {43 00 61 00 70 00 74 00 69 00 6f 00 6e 00 [0-16] 53 00 65 00 74 00 75 00 70 00 5f 00 70 00 72 00 6f 00 64 00 75 00 63 00 74 00}  //weight: 3, accuracy: Low
        $x_1_19 = "WM_HTML_GETOBJECT" wide //weight: 1
        $x_1_20 = "Internet Explorer_Server" wide //weight: 1
        $x_1_21 = {53 00 74 00 72 00 69 00 6e 00 67 00 46 00 69 00 6c 00 65 00 49 00 6e 00 66 00 6f 00 [0-16] 30 00 34 00 30 00 39 00 30 00 34 00 42 00 30 00}  //weight: 1, accuracy: Low
        $x_1_22 = {46 69 6e 64 57 69 6e 64 6f 77 41 00}  //weight: 1, accuracy: High
        $x_1_23 = {53 68 6f 77 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
        $x_2_24 = {53 00 65 00 6c 00 65 00 63 00 74 00 20 00 2a 00 20 00 66 00 72 00 6f 00 6d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 [0-16] 77 00 69 00 6e 00 6d 00 67 00 6d 00 74 00 73 00 3a 00 [0-16] 45 00 78 00 65 00 63 00 51 00 75 00 65 00 72 00 79 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 6 of ($x_1_*))) or
            ((2 of ($x_2_*) and 4 of ($x_1_*))) or
            ((3 of ($x_2_*) and 2 of ($x_1_*))) or
            ((4 of ($x_2_*))) or
            ((1 of ($x_3_*) and 5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_3_*) and 3 of ($x_2_*))) or
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*) and 1 of ($x_2_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

