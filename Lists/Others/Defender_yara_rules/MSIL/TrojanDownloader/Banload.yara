rule TrojanDownloader_MSIL_Banload_2147663696_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload"
        threat_id = "2147663696"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5c 6c 6b 70 72 6f 63 5c 6c 6b 70 72 6f 63 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c 6c 6b 70 72 6f 63 2e 70 64 62 00}  //weight: 1, accuracy: High
        $x_1_2 = "\\unzip.exe" wide //weight: 1
        $x_1_3 = "-P RwXpLPaz#$56&x dreamx.zip" wide //weight: 1
        $x_1_4 = {6c 00 6b 00 70 00 72 00 6f 00 63 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_MSIL_Banload_L_2147692026_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.L"
        threat_id = "2147692026"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 00 65 00 73 00 74 00 65 00 20 00 30 00 31 00 00 13 74 00 65 00 73 00 74 00 65 00 20 00 30 00 38 00 37 00 00 [0-2] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_M_2147692165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.M"
        threat_id = "2147692165"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tco03.exe" ascii //weight: 1
        $x_1_2 = {53 65 72 76 65 72 43 6f 6d 70 75 74 65 72 00 4e 65 74 77 6f 72 6b 00 67 65 74 5f 4e 65 74 77 6f 72 6b 00 50 69 6e 67 00 44 6f 77 6e 6c 6f 61 64 46 69 6c 65}  //weight: 1, accuracy: High
        $x_1_3 = {2e 00 65 00 78 00 65 00 00 23 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_N_2147692685_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.N"
        threat_id = "2147692685"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 69 00 6d 00 61 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 [0-10] 68 00 74 00 74 00 70 00}  //weight: 2, accuracy: Low
        $x_1_2 = "\\Banks\\Loaders" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_N_2147692685_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.N"
        threat_id = "2147692685"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "\\Application Data\\imadwm.exe" ascii //weight: 5
        $x_2_2 = {5c 4c 6f 61 64 65 72 20 56 62 [0-1] 6e 65 74 5c}  //weight: 2, accuracy: Low
        $x_2_3 = {5c 00 69 00 6d 00 61 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 [0-8] 55 00 73 00 65 00 72 00 2d 00 41 00 67 00 65 00 6e 00 74 00 [0-8] 4d 00 6f 00 7a 00 69 00 6c 00 6c 00 61 00 [0-16] 68 00 74 00 74 00 70 00 3a 00}  //weight: 2, accuracy: Low
        $x_2_4 = "Exemplo: \"Update terminado. Obrigado.\"" wide //weight: 2
        $x_2_5 = "Exemplo: \"O update do flash" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*))) or
            ((1 of ($x_5_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_O_2147692760_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.O"
        threat_id = "2147692760"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 69 00 6d 00 61 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 [0-10] 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {20 30 75 00 00 28 ?? 00 00 0a 00 73 ?? 00 00 0a 0b 07 72 ?? ?? 00 70 06 72 ?? ?? 00 70 28 ?? 00 00 0a 6f ?? 00 00 0a 00 de 0f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_P_2147693085_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.P"
        threat_id = "2147693085"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_downLoadFile" ascii //weight: 1
        $x_1_2 = "_filedown" ascii //weight: 1
        $x_1_3 = {64 65 63 72 69 70 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 53 51 4c 43 6f 6e 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {5f 53 51 4c 43 6d 64 00}  //weight: 1, accuracy: High
        $x_3_6 = {06 0d 09 02 7b ?? 00 00 04 73 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 74 ?? 00 00 1b}  //weight: 3, accuracy: Low
        $x_3_7 = {06 13 05 11 05 02 7b ?? 00 00 04 73 ?? 00 00 0a 13 04 11 04 6f ?? 00 00 0a 74 ?? 00 00 1b}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 3 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_P_2147693085_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.P"
        threat_id = "2147693085"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6f 77 6e 4c 6f 61 64 46 69 6c 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {64 65 63 72 69 70 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {5f 53 51 4c 43 6f 6e 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {5f 53 51 4c 43 6d 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 62 61 69 78 61 [0-48] 5c}  //weight: 1, accuracy: Low
        $x_1_6 = "\\downloadloiad\\downloadloiad\\" ascii //weight: 1
        $x_2_7 = {00 70 6f 2f 00 00 06 0d 09 02 7b ?? 00 00 04 73 ?? 00 00 0a 0c 08 6f ?? 00 00 0a 74 0c 00 00 1b 0a 02 7b ?? 00 00 04 72 ?? ?? 00 70 09 00 02 7b ?? 00 00 04 72}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_Q_2147693086_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.Q"
        threat_id = "2147693086"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_Primario_1" ascii //weight: 1
        $x_1_2 = "Modulo_Primario" ascii //weight: 1
        $x_1_3 = {61 00 72 00 71 00 75 00 69 00 76 00 6f 00 20 00 65 00 73 00 74 00 e1 00 20 00 64 00 61 00 6e 00 69 00 66 00 69 00 63 00 61 00 64 00 6f 00 20 00 65 00 20 00 6e 00 e3 00 6f 00 20 00 70 00 6f 00 64 00 65 00 20 00 73 00 65 00 72 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 61 00 64 00 6f 00 20 00 21 00}  //weight: 1, accuracy: High
        $x_1_4 = {3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? [0-24] 2e 00 (65 00 78|63 00 70) 00 [0-5] 68 00 74 00 74 00 70 00 3a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_MSIL_Banload_R_2147693999_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.R"
        threat_id = "2147693999"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Tco03.exe" ascii //weight: 1
        $x_1_2 = {2e 00 65 00 78 00 65 00 00 23 77 00 77 00 77 00 2e 00 67 00 6f 00 6f 00 67 00 6c 00 65 00 2e 00 63 00 6f 00 6d 00 2e 00 62 00 72}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\arqText.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_S_2147694060_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.S"
        threat_id = "2147694060"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5c 00 69 00 6d 00 61 00 64 00 77 00 6d 00 2e 00 65 00 78 00 65 00 [0-10] 68 00 74 00 74 00 70 00}  //weight: 2, accuracy: Low
        $x_1_2 = ".vmp.scr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_T_2147694552_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.T"
        threat_id = "2147694552"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 00 75 00 63 00 6b 00 65 00 72 00 ?? ?? ?? ?? 23 00}  //weight: 1, accuracy: Low
        $x_1_2 = {66 75 63 6b 65 72 ?? ?? ?? ?? 23}  //weight: 1, accuracy: Low
        $x_1_3 = "flashp.exe" wide //weight: 1
        $x_1_4 = "gordo.zip" wide //weight: 1
        $x_1_5 = {72 01 00 00 70 0a 72 ?? 00 00 70 0b 72 ?? 00 00 70 0c 72 ?? 00 00 70 0d 1f 1a 28 01 00 00 0a 13 04 20 30 75 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_MSIL_Banload_T_2147694552_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.T"
        threat_id = "2147694552"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "flashp.exe" wide //weight: 1
        $x_1_2 = "DownloadFile" wide //weight: 1
        $x_1_3 = "\\unzip.exe" wide //weight: 1
        $x_1_4 = "Ba6WkwUmkfv0r3Ar4L3Q1g==" wide //weight: 1
        $x_1_5 = "baleia.zip" wide //weight: 1
        $x_1_6 = "molde.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_MSIL_Banload_T_2147694552_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.T"
        threat_id = "2147694552"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "urldakl" ascii //weight: 1
        $x_1_2 = {6e 6f 6d 65 64 (6f 7a|61)}  //weight: 1, accuracy: Low
        $x_1_3 = "unzip.exe" wide //weight: 1
        $x_2_4 = {66 00 75 00 63 00 6b 00 65 00 72 00 ?? ?? ?? ?? 23 00}  //weight: 2, accuracy: Low
        $x_2_5 = {66 75 63 6b 65 72 ?? ?? ?? ?? 23}  //weight: 2, accuracy: Low
        $x_2_6 = {6d 00 6f 00 64 00 2e 00 7a 00 69 00 70 00 [0-4] 68 00 74 00 74 00 70 00}  //weight: 2, accuracy: Low
        $x_2_7 = {66 00 6c 00 61 00 73 00 68 00 70 00 [0-16] 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00}  //weight: 2, accuracy: Low
        $x_2_8 = {0a 02 02 fe 06 ?? 00 00 06 73 ?? 00 00 0a 28 ?? 00 00 0a [0-1] 02 1f 1a 28 ?? 00 00 0a 7d 01 00 00 04 02 72 01 00 00 70 7d 02 00 00 04 02 72 ?? 00 00 70 7d 03 00 00 04 02 72 ?? 00 00 70 7d 04 00 00 04 02 72 ?? 00 00 70 7d 05 00 00 04 02}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_U_2147695044_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.U"
        threat_id = "2147695044"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "linkdakl" ascii //weight: 1
        $x_1_2 = {6e 6f 6d 65 64 (6f 7a|61)}  //weight: 1, accuracy: Low
        $x_1_3 = "unzip.exe" wide //weight: 1
        $x_1_4 = "Banks\\Loaders" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_V_2147695403_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.V"
        threat_id = "2147695403"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 70 0a 06 17 28 (02|05) 00 00 06 0b 07 0c 1f 1a 28 ?? 00 00 0a 0d 09 72 ?? 00 00 70 28 ?? 00 00 0a 13 04}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 4f 00 4e 00 43 00 4c 00 55 00 49 00 52 00 [0-6] 62 00 75 00 74 00 74 00 6f 00 6e 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 65 00 63 00 68 00 61 00 72 00 [0-6] 74 00 65 00 78 00 74 00 42 00 6f 00 78 00}  //weight: 1, accuracy: Low
        $x_1_4 = "c:\\Users\\PROVIDER\\Desktop\\SOPA\\LOAD_EXE" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_MSIL_Banload_W_2147696254_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.W"
        threat_id = "2147696254"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 6f 00 64 00 65 00 20 00 73 00 65 00 72 00 20 00 65 00 78 00 65 00 63 00 75 00 74 00 61 00 64 00 6f 00 20 00 21 00 ?? ?? 45 00 72 00 72 00 6f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 ?? ?? 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 61 00 74 00 69 00 65 00 63 00 6c 00 78 00 78 00 2e 00 63 00 70 00 6c 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\ProgramData\\FiddlerCore.dll" wide //weight: 1
        $x_1_4 = "\\ProgramData\\makecert.exe" wide //weight: 1
        $x_1_5 = {5c 4c 6f 61 64 65 72 20 43 23 20 43 72 79 70 74 65 72 [0-3] 5c 6f 62 6a 5c 78 38 36 5c 44 65 62 75 67 5c}  //weight: 1, accuracy: Low
        $x_1_6 = "http://www.inovador" wide //weight: 1
        $x_1_7 = {5c 4d 6f 64 20 [0-6] 20 56 42 2e 4e 45 54 [0-6] 5c 46 69 6c 65 20 44 6f 77 6e 6c 6f 61 64 65 72 5c 6f 62 6a 5c 44 65 62 75 67 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanDownloader_MSIL_Banload_Y_2147697198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.Y"
        threat_id = "2147697198"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Mod Loader" ascii //weight: 1
        $x_1_2 = "\\Testes Loades" ascii //weight: 1
        $x_1_3 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 ?? ?? 50 00 6f 00 72 00 74 00 75 00 67 00 75 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 63 00 70 00 6c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_MSIL_Banload_Y_2147697198_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.Y"
        threat_id = "2147697198"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 4f 00 62 00 6a 00 65 00 63 00 74 00 2e 00 63 00 70 00 6c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 61 00 72 00 6d 00 73 00 76 00 63 00 33 00 32 00 2e 00 63 00 70 00 6c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_3 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 66 00 69 00 78 00 2e 00 63 00 70 00 6c 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 2, accuracy: Low
        $x_2_4 = {2e 00 65 00 6e 00 63 00 ?? ?? 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-16] 2e 00 65 00 6e 00 63 00 ?? ?? 43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 61 00 72 00 6d 00 73 00 76 00 63 00 33 00 32 00 2e 00 63 00 70 00 6c 00}  //weight: 2, accuracy: Low
        $x_1_5 = {50 52 4f 4a 45 54 4f 20 [0-48] 4c 6f 61 64 65 72 73 [0-16] 45 78 65 6d 70 6c 6f 20 55 6d [0-4] 5c 6f 62 6a 5c 44 65 62 75 67 5c}  //weight: 1, accuracy: Low
        $x_1_6 = "D:\\Exemplo Um 1\\obj\\Debug\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_Z_2147706316_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.Z"
        threat_id = "2147706316"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-16] 2e 00 7a 00 69 00 70 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {43 00 3a 00 5c 00 50 00 72 00 6f 00 67 00 72 00 61 00 6d 00 44 00 61 00 74 00 61 00 5c 00 [0-16] 2e 00 63 00 70 00 6c 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 37 00 39 00 2e 00 31 00 38 00 38 00 2e 00 33 00 38 00 2e 00 34 00 32 00 2f 00 [0-21] 2e 00 7a 00 69 00 70 00 00}  //weight: 1, accuracy: Low
        $x_2_4 = "D:\\RODANDO\\PROJETO PG SUBZID\\Mod Loaders\\Exemplo Dois 2\\obj\\Debug\\j2_2.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AA_2147706341_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AA"
        threat_id = "2147706341"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 53 00 65 00 65 00 49 00 6e 00 6e 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 [0-3] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 ?? ?? 5c 00 75 00 6e 00 7a 00 69 00 70 00 2e 00 65 00 78 00 65 00 ?? ?? 20 00 ?? ?? 75 00 6e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Users\\Admin\\Desktop\\Lord\\Lord ZIP" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AB_2147706585_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AB"
        threat_id = "2147706585"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6c 00 75 00 6d 00 61 00 2e 00 7a 00 69 00 70 00 [0-4] 72 00 75 00 6e 00 61 00 73 00 [0-16] 5c 00 00 [0-4] 2e 00 65 00 78 00 65 00 00 [0-16] 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 00 [0-255] 6d 00 6f 00 78 00 2e 00 65 00 78 00 65 00 [0-255] 57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 52 00 65 00 63 00 75 00 72 00 73 00 69 00 76 00 65 00 46 00 6f 00 72 00 6d 00 43 00 72 00 65 00 61 00 74 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AB_2147706585_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AB"
        threat_id = "2147706585"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {4c 00 61 00 62 00 65 00 6c 00 32 00 ?? ?? 68 00 74 00 74 00 70 00 [0-128] 73 00 69 00 6e 00 63 00 72 00 6f 00 6e 00 69 00 73 00 6d 00 6f 00 ?? ?? 46 00 6f 00 72 00 6d 00 31 00 ?? ?? 72 00 75 00 6e 00 61 00 73 00 ?? ?? 5c 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_2 = "\\Admin\\Desktop\\Saxo\\Saxo\\" ascii //weight: 1
        $x_1_3 = {49 73 55 73 65 72 41 64 6d 69 6e 69 73 74 72 61 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "/UnZip.html" wide //weight: 1
        $x_2_5 = {43 00 68 00 65 00 63 00 6b 00 42 00 6f 00 78 00 34 00 ?? ?? 68 00 74 00 74 00 70 00 [0-128] 4c 00 65 00 73 00 73 00 61 00 ?? ?? 74 00 75 00 70 00 69 00 73 00 2e 00 7a 00 69 00 70 00 ?? ?? 72 00 75 00 6e 00 61 00 73 00 ?? ?? 5c 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 2, accuracy: Low
        $x_1_6 = "\\Admin\\Desktop\\Product\\Product\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_AB_2147706585_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AB"
        threat_id = "2147706585"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 20 00 7b 00 30 00 7d 00 [0-3] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4d 79 53 65 74 74 69 6e 67 73 50 72 6f 70 65 72 74 79 [0-7] 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_3 = {53 70 65 63 69 61 6c 44 69 72 65 63 74 6f 72 69 65 73 50 72 6f 78 79 [0-6] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_4 = {44 00 69 00 61 00 6c 00 6f 00 67 00 31 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_5 = {57 00 69 00 6e 00 46 00 6f 00 72 00 6d 00 73 00 5f 00 53 00 65 00 65 00 49 00 6e 00 6e 00 65 00 72 00 45 00 78 00 63 00 65 00 70 00 74 00 69 00 6f 00 6e 00 ?? ?? 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_6 = {72 00 75 00 6e 00 61 00 73 00 ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00 ?? ?? 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_7 = {2e 00 65 00 78 00 65 00 ?? ?? 25 00 61 00 70 00 70 00 64 00 61 00 74 00 61 00 25 00 ?? ?? 5c 00 [0-32] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = "\\users\\ecology\\documents\\visual studio 2015\\Projects\\nomar" ascii //weight: 1
        $x_1_9 = {46 00 6f 00 72 00 6d 00 31 00 ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00 ?? ?? 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 ?? ?? 5c 00}  //weight: 1, accuracy: Low
        $x_1_10 = {2e 00 65 00 78 00 65 00 ?? ?? 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 46 00 69 00 6c 00 65 00 ?? ?? 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AD_2147706805_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AD"
        threat_id = "2147706805"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3a 5c 55 73 65 72 73 5c 41 64 6d 69 6e 5c 44 65 73 6b 74 6f 70 5c 4c 6f 72 64 31 5c 47 58 5c 47 58 5c 6f 62 6a 5c 78 38 36 5c 52 65 6c 65 61 73 65 5c [0-31] 2e 70 64 62 00}  //weight: 1, accuracy: Low
        $x_1_2 = {24 31 30 38 32 66 39 66 36 2d 32 36 36 31 2d 34 65 63 65 2d 62 32 65 64 2d 65 61 61 36 34 32 34 33 35 64 35 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "uixpqox.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AE_2147706831_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AE"
        threat_id = "2147706831"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\UPDTHPP\\key.cel" wide //weight: 1
        $x_1_2 = "TotalCommander." wide //weight: 1
        $x_1_3 = "Key_Cel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AF_2147706887_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AF"
        threat_id = "2147706887"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {13 0a 11 0a 16 1f 7c 9d 11 0a 6f}  //weight: 1, accuracy: High
        $x_1_2 = {06 1f 29 16 28}  //weight: 1, accuracy: High
        $x_1_3 = "[^A-Za-z0-9]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AF_2147706887_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AF"
        threat_id = "2147706887"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 e8 03 00 00 20 0f 27 00 00 6f}  //weight: 1, accuracy: High
        $x_1_2 = {2b 07 1f 64 28 ?? ?? ?? ?? 7e ?? ?? ?? ?? 6f ?? ?? ?? ?? 2d ed}  //weight: 1, accuracy: Low
        $x_1_3 = ".exe?dl=1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AG_2147706893_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AG"
        threat_id = "2147706893"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 72 6c 64 61 6b 6c 00 6e 6f 6d 65 64 6f 7a 69 70 00 73 65 6e 68 61 64 6f 7a 69 70 00 6e 6f 6d 65 64 6f 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 00 6f 00 70 00 69 00 63 00 73 00 2e 00 7a 00 69 00 70 00 ?? ?? ?? ?? 64 00 66 00 67 00 78 00 2e 00 65 00 78 00 65 00 ?? ?? 72 00 75 00 6e 00 61 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AH_2147707239_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AH"
        threat_id = "2147707239"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {72 00 75 00 6e 00 61 00 73 00 ?? ?? 5c 00 7a 00 78 00 54 00 6f 00 72 00 72 00 65 00 6e 00 74 00 ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_2 = {72 00 75 00 6e 00 61 00 73 00 ?? ?? 5c 00 46 00 6c 00 61 00 73 00 68 00 50 00 6c 00 61 00 79 00 ?? ?? ?? ?? ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_3 = {72 00 75 00 6e 00 61 00 73 00 ?? ?? 5c 00 4d 00 65 00 64 00 69 00 61 00 58 00 ?? ?? 5c 00}  //weight: 10, accuracy: Low
        $x_10_4 = {72 00 75 00 6e 00 61 00 73 00 ?? ?? 5c 00 41 00 64 00 6f 00 62 00 65 00 50 00 6c 00 61 00 79 00 ?? ?? 5c 00}  //weight: 10, accuracy: Low
        $x_10_5 = {45 00 6e 00 61 00 62 00 6c 00 65 00 4c 00 55 00 41 00 ?? ?? ?? ?? ?? ?? 5c 00 41 00 64 00 6f 00 62 00 65 00 50 00 6c 00 61 00 79 00 ?? ?? 5c 00 ?? ?? 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_1_6 = "ZIPINFOOPT" ascii //weight: 1
        $x_1_7 = {4c 00 61 00 62 00 65 00 6c 00 32 00 ?? ?? 68 00 74 00 74 00 70 00 [0-1] 3a 00 2f 00 2f 00}  //weight: 1, accuracy: Low
        $x_1_8 = "IsUserAdministrator" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_AK_2147707648_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AK"
        threat_id = "2147707648"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 00 61 00 69 00 74 00 65 00 78 00 61 00 ?? ?? 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 32 00 ?? ?? 4c 00 61 00 62 00 65 00 6c 00 32 00 ?? ?? 68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2f 00 [0-16] 2e 00 7a 00 69 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {72 00 75 00 6e 00 61 00 73 00 [0-32] 43 00 68 00 65 00 63 00 6b 00 42 00 6f 00 78 00 35 00}  //weight: 1, accuracy: Low
        $x_1_3 = {2e 65 78 65 00 73 65 74 5f 53 69 7a 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AL_2147707740_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AL"
        threat_id = "2147707740"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 74 00 75 00 62 00 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 ?? ?? 68 00 74 00 74 00 70 00}  //weight: 1, accuracy: Low
        $x_1_2 = {65 00 73 00 70 00 65 00 72 00 61 00 54 00 68 00 72 00 65 00 61 00 64 00 ?? ?? 42 00 75 00 74 00 74 00 6f 00 6e 00 31 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5c 00 74 00 65 00 6d 00 70 00 6c 00 63 00 2e 00 65 00 78 00 65 00 ?? ?? 25 00 44 00 4f 00 57 00 4e 00 32 00 25 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AM_2147708159_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AM"
        threat_id = "2147708159"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://millioncarros.com.br/carshdbfv.zip" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AM_2147708159_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AM"
        threat_id = "2147708159"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {4c 00 61 00 62 00 65 00 6c 00 32 00 [0-8] 68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00}  //weight: 10, accuracy: Low
        $x_10_2 = "ventx.zip" wide //weight: 10
        $x_10_3 = {4e 00 61 00 6d 00 65 00 53 00 70 00 61 00 63 00 65 00 ?? ?? ?? ?? ?? ?? [0-6] 2e 00 7a 00 69 00 70 00 ?? ?? [0-2] 43 00 6f 00 70 00 79 00 48 00 65 00 72 00 65 00}  //weight: 10, accuracy: Low
        $x_1_4 = {55 6e 5a 69 70 00 73 65 74 5f 54 61 62 53 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_5 = {53 6c 65 65 70 00 73 65 74 5f 54 61 62 53 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_6 = {52 69 70 00 73 65 74 5f 54 61 62 53 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_7 = {42 6f 78 38 00 73 65 74 5f 54 61 62 53 74 6f 70 00}  //weight: 1, accuracy: High
        $x_1_8 = {78 7a 63 76 00 73 65 74 5f 54 61 62 49 6e 64 65 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_AN_2147708499_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AN"
        threat_id = "2147708499"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VVCgRoB8kWItk5d+WrcV8A==" wide //weight: 1
        $x_1_2 = "\\showKL" wide //weight: 1
        $x_10_3 = {35 00 34 00 36 00 38 00 37 00 32 00 36 00 35 00 36 00 31 00 36 00 34 00 36 00 39 00 36 00 45 00 36 00 37 00 34 00 44 00 36 00 46 00 36 00 34 00 36 00 35 00 36 00 43 00 ?? ?? 42 00 6f 00 74 00 68 00 ?? ?? 53 00 4f 00 46 00 54 00}  //weight: 10, accuracy: Low
        $x_10_4 = {6c 00 69 00 6e 00 6b 00 3d 00 ?? ?? ?? ?? 64 00 6e 00 73 00 3d 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_AQ_2147708960_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AQ"
        threat_id = "2147708960"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {2e 00 7a 00 69 00 70 00 ?? ?? 43 00 6f 00 70 00 79 00 48 00 65 00 72 00 65 00 ?? ?? 49 00 74 00 65 00 6d 00 73 00 ?? ?? 72 00 75 00 6e 00 61 00 73 00 ?? ?? 5c 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 10, accuracy: Low
        $x_10_2 = {25 16 02 7b 08 00 00 04 72 89 00 00 70 28 ?? 00 00 06 6f ?? 00 00 06 72 8d 00 00 70 28 ?? 00 00 0a a2 14}  //weight: 10, accuracy: Low
        $x_1_3 = {2e 7a 69 70 [0-6] 54 53 50 6c 61 79 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 7a 69 70 [0-6] 44 72 6f 70 58}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 7a 69 70 [0-6] 41 66 74 65 72 58}  //weight: 1, accuracy: Low
        $x_1_6 = {44 72 6f 70 58 [0-6] 68 74 74 70 3a 2f 2f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_AR_2147709367_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AR"
        threat_id = "2147709367"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {52 65 6d 6f 76 65 00 66 63 6b 2e 65 78 65}  //weight: 10, accuracy: High
        $x_10_2 = "fck.Resources" ascii //weight: 10
        $x_1_3 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f [0-10] 68 74 74 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AR_2147709367_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AR"
        threat_id = "2147709367"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "\\WireX\\acim.exe" wide //weight: 10
        $x_10_2 = "\\WireX\\vox.zip" wide //weight: 10
        $x_1_3 = {2e 7a 69 70 ?? ?? ?? ?? ?? ?? 4d 79 2e 53 65 74 74 69 6e 67 73}  //weight: 1, accuracy: Low
        $x_1_4 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f [0-10] 68 74 74 70}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_AR_2147709367_2
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AR"
        threat_id = "2147709367"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 69 73 70 6f 73 65 5f 5f 49 6e 73 74 61 6e 63 65 5f 5f [0-10] 68 74 74 70}  //weight: 1, accuracy: Low
        $x_1_2 = {2e 7a 69 70 [0-8] 4d 79 2e 53 65 74 74 69 6e 67 73 [0-8] 4d 79 2e 43 6f 6d 70 75 74 65 72}  //weight: 1, accuracy: Low
        $x_10_3 = {13 06 11 06 28 ?? ?? 00 06 6f ?? ?? 00 06 6f ?? ?? 00 0a 13 05 72 ?? ?? 00 70 28 ?? ?? 00 0a 13 07 02 6f ?? ?? 00 06 11 07 72 ?? ?? 00 70 28 ?? ?? 00 0a 6f ?? ?? 00 0a 00 11 07 72 ?? ?? 00 70 28 ?? ?? 00 06 6f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AS_2147710198_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AS"
        threat_id = "2147710198"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\3load\\" ascii //weight: 1
        $x_1_2 = "C:\\2load\\" ascii //weight: 1
        $x_1_3 = "explorer C:\\" wide //weight: 1
        $x_10_4 = {73 36 00 00 0a 80 0a 00 00 04 72 c5 00 00 70 72 ?? 01 00 70 28 ?? 00 00 06 80 ?? 00 00 04 72 ?? 01 00 70 72 ?? 01 00 70 28 ?? 00 00 06 80 ?? 00 00 04 73 37 00 00 0a 80 ?? 00 00 04 2a}  //weight: 10, accuracy: Low
        $x_10_5 = {1f 20 8d 39 00 00 01 13 ?? ?? 28 3a 00 00 0a 03 6f 3b 00 00 0a 6f 3c 00 00 0a 13 ?? 11 ?? 16 11 ?? 16 1f 10 28 3d 00 00 0a}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_AT_2147710759_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AT"
        threat_id = "2147710759"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\ARQUIVO.ZIP" wide //weight: 1
        $x_1_2 = "REG.KAYC" wide //weight: 1
        $x_1_3 = "LOAD_G0LP3\\obj" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_AU_2147728157_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.AU!bit"
        threat_id = "2147728157"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 6a 00 6d 00 78 00 73 00 61 00 63 00 61 00 62 00 61 00 6d 00 65 00 6e 00 74 00 6f 00 73 00 67 00 72 00 61 00 66 00 69 00 63 00 6f 00 73 00 2e 00 63 00 6f 00 6d 00 2f 00 [0-64] 2e 00 7a 00 69 00 70 00}  //weight: 3, accuracy: Low
        $x_1_2 = "/post.php?sel=" wide //weight: 1
        $x_1_3 = "(?<=<CountryCode>).+(?=</CountryCode>)" wide //weight: 1
        $x_1_4 = "pt-BR" wide //weight: 1
        $x_1_5 = "Server" wide //weight: 1
        $x_1_6 = "\\msconfig.ini" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Banload_A_2147731658_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.A!MTB"
        threat_id = "2147731658"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/roommaster.exe" wide //weight: 1
        $x_1_2 = "http://oficinafinancieiro.website" wide //weight: 1
        $x_1_3 = "$443b4146-d26c-4e3d-8229-3f09a3b004ed" ascii //weight: 1
        $x_1_4 = {72 2d 00 00 70 28 48 00 00 0a 26}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_MSIL_Banload_ABN_2147845008_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.ABN!MTB"
        threat_id = "2147845008"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {26 18 13 0e 2b a6 04 20 c7 95 a4 0b 61 03 61 0a 7e 02 00 00 04 0c 08 74 01 00 00 1b 25 06 93 0b 06 18 58 93 07 61 0b 19 13 0e 2b 80 7e 03 00 00 04 74 02 00 00 1b 07 9a 25 0d}  //weight: 2, accuracy: High
        $x_1_2 = "dizipal.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_MSIL_Banload_ABL_2147851749_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Banload.ABL!MTB"
        threat_id = "2147851749"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Banload"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {16 13 0b 2b 1a 11 15 11 0b 9a 13 16 11 16 17 28 ?? ?? ?? 0a de 03 26 de 00 11 0b 17 58 13 0b 11 0b 11 15 8e 69 32 de}  //weight: 2, accuracy: Low
        $x_1_2 = "source\\repos\\GsmRemoteService\\GsmRemoteService\\obj\\Release\\GsmRemoteService.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

