rule VirTool_MSIL_Injector_A_2147638708_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!A"
        threat_id = "2147638708"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 04 20 00 30 00 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_2 = {00 00 04 20 00 30 00 00 1f 40 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_3 = {20 50 45 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 00 04 20 4d 5a 00 00}  //weight: 1, accuracy: High
        $x_3_5 = {02 12 05 7c ?? 00 00 04 7b ?? 00 00 04 6e 28 ?? 00 00 0a 11 09 84 13 18 12 18 28 ?? 00 00 06}  //weight: 3, accuracy: Low
        $x_3_6 = "WriteProcessMemory" ascii //weight: 3
        $x_3_7 = "ZwUnmapViewOfSection" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 3 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_D_2147640282_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.D"
        threat_id = "2147640282"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 04 91 58 20 00 01 00 00 5d 13 06 02 50 11 05 8f 11 00 00 01 25 71 11 00 00 01 06 11 06 91 61 d2 81 11 00 00 01}  //weight: 1, accuracy: High
        $x_1_2 = {20 50 45 00 00 33 0e 12 00 7b ?? 00 00 04 20 4d 5a 00 00 2e 02}  //weight: 1, accuracy: Low
        $x_1_3 = {11 11 17 58 13 11 11 11 12 02 7b ?? 00 00 04 17 59 31 d9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_E_2147640283_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.E"
        threat_id = "2147640283"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 2a 07 11 05 02 11 05 91 09 61 06 11 04 91 61 b4 9c 11 04 06 8e b7 17 da 33 05 16 13 04 2b 06}  //weight: 1, accuracy: High
        $x_1_2 = {11 0e 11 0c 20 00 30 00 00 1f 40 6f ?? 00 00 06 13 0f 7e 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_F_2147640292_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.F"
        threat_id = "2147640292"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 91 07 61 08 06 91 61 b4 9c 06 08 8e b7 17 da 33 04}  //weight: 1, accuracy: High
        $x_1_2 = {11 0e 11 0c 20 00 30 00 00 1f 40 6f ?? 00 00 06 13 0f 7e}  //weight: 1, accuracy: Low
        $x_1_3 = {38 8b 00 00 00 1f 0a 8d ?? 00 00 01 13 12 02 11 04 20 f8 00 00 00 d6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_J_2147641205_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.J"
        threat_id = "2147641205"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {20 f8 00 00 00 d6 6a 13 ?? 16 12 ?? 7c ?? ?? ?? ?? 7b ?? ?? ?? ?? 17 da 13 2e 13 ?? 38}  //weight: 2, accuracy: Low
        $x_2_2 = {20 50 45 00 00 6a fe 01}  //weight: 2, accuracy: High
        $x_1_3 = {11 05 02 11 05 91 [0-2] 61}  //weight: 1, accuracy: Low
        $x_1_4 = {04 20 00 01 00 00 d6 b5 10 02 04 16 32 f2}  //weight: 1, accuracy: High
        $x_1_5 = "WriteProcessMemory" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_K_2147642092_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.K"
        threat_id = "2147642092"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {52 66 68 6e 20 4d 18 22 76 b5 33 11 12 33 0c 6d 0a 20 4d 18 22 9e a1 29 61 1c 76 b5 05 19 01 58}  //weight: 1, accuracy: High
        $x_1_2 = "FuckJagex.com_s_Binder_Stub" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_O_2147644644_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.O"
        threat_id = "2147644644"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "N0$crypter" ascii //weight: 1
        $x_1_2 = "fkoff" ascii //weight: 1
        $x_1_3 = {5d 00 00 06 20 e8 03 00 00 28 06 00 00 0a de 0c}  //weight: 1, accuracy: High
        $x_1_4 = {07 11 04 11 08 6f 2a 00 00 0a 16}  //weight: 1, accuracy: High
        $x_1_5 = {10 00 00 0a 07 16 6f 11 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_B_2147644898_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!B"
        threat_id = "2147644898"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 6f 6c 79 44 65 63 00 49 6e 70 75 74 00 4b 69 6c 6c 65 72}  //weight: 1, accuracy: High
        $x_1_2 = {52 65 76 65 72 73 65 53 74 72 69 6e 67 00 73 00 43 53 68 61 72 70}  //weight: 1, accuracy: High
        $x_1_3 = {43 53 68 61 72 70 00 53 79 73 44 4c 4c 00 53 79 73 4d 61 6e 61 67 65 6d 65 6e 74 00 50 6c 61 74 46 6f 72 6d 38 36 42 69 74}  //weight: 1, accuracy: High
        $x_1_4 = {58 49 20 73 73 61 6c 63 20 63 69 6c 62 75 70 0a 0d 3b 74 78 65 54 2e 6d 65 74 73 79 53 20 67 6e 69 73 75 0a 0d 3b 6d 65 74 73 79 53 20 67 6e 69 73 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Injector_E_2147647437_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!E"
        threat_id = "2147647437"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PASSWIN" wide //weight: 1
        $x_1_2 = "%WINLOGON%" wide //weight: 1
        $x_1_3 = "\\v2.0.50727\\vbc.exe" wide //weight: 1
        $x_1_4 = "Configurable_Injector.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_F_2147647601_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!F"
        threat_id = "2147647601"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-4] 73 00 76 00 63 00 68 00 6f 00 73 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {03 00 70 6f 06 00 00 06 06 72 ?? ?? 00 70 6f 06 00 00 06 28 05 00 00 2b 13 05 02 06}  //weight: 1, accuracy: Low
        $x_1_3 = {49 20 4d 5a 00 00 2e 02 16 2a 11 10 1f 3c d3 58 4a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_MSIL_Injector_T_2147647766_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.T"
        threat_id = "2147647766"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 07 02 07 91 03 07 06 5d 91 61 28 ?? 00 00 0a 9c 07 17 58 0b 07 02 8e 69 32 e5}  //weight: 1, accuracy: Low
        $x_1_2 = {d3 58 4b 20 00 30 00 00 1f 40 6f ?? 00 00 06 7e ?? 00 00 0a 28 ?? 00 00 0a 2c 09}  //weight: 1, accuracy: Low
        $x_1_3 = {13 06 1f 28 8d ?? 00 00 01 13 07 20 f8 00 00 00 8d ?? 00 00 01 13 08 1f 40 8d}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_U_2147648199_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!U"
        threat_id = "2147648199"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 15 00 00 0a 21 ?? ?? ?? ?? ?? ?? ce 08 73 16 00 00 0a 28 17 00 00 0a 2c 06 73 18 00 00 0a 7a}  //weight: 1, accuracy: Low
        $x_1_2 = {62 75 74 65 00 ee 80 81 00 ee 80 82 00 ee 80 83 00 56 65 72}  //weight: 1, accuracy: High
        $x_1_3 = "ef63g8g8-8g53" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_W_2147648492_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!W"
        threat_id = "2147648492"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6e 74 69 44 65 62 75 67 67 65 72 00 61 6e 74 69 45 6d 75 6c 61 74 6f 72}  //weight: 1, accuracy: High
        $x_1_2 = {61 6e 74 69 52 65 67 4d 6f 6e 00 61 6e 74 69 53 61 6e 64 62 6f 78 69 65}  //weight: 1, accuracy: High
        $x_1_3 = {66 61 6b 65 45 72 72 6f 72 00 66 61 6b 65 45 72 72 6f 72 54 69 74 6c 65}  //weight: 1, accuracy: High
        $x_1_4 = {64 69 73 61 62 6c 65 46 69 72 65 77 61 6c 6c 00 64 69 73 61 62 6c 65 52 65 67 69 73 74 72 79}  //weight: 1, accuracy: High
        $x_1_5 = {19 41 00 75 00 64 00 69 00 6f 00 20 00 44 00 65 00 76 00 69 00 63 00 65 00 00 1d 47 00 72 00 61 00 70 00 68 00 69 00 63}  //weight: 1, accuracy: High
        $x_2_6 = {02 08 07 6f 08 00 00 0a 13 04 12 04 28 09 00 00 0a 0d 09 2c 0d 06 09 28 0a 00 00 0a 6f 0b 00 00 0a 26 08 17 58 0c 08 02 6f 0c 00 00 0a 32 d1}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_G_2147648809_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!G"
        threat_id = "2147648809"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "}};#urt nrut#r;)" ascii //weight: 1
        $x_1_2 = {4d 61 69 6e 00 52 65 76 65 72 73 65 72 00 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {05 46 00 46 00 00 05 53 00 53 00 00 05 54 00 54 00 00 05 55 00 55 00}  //weight: 1, accuracy: High
        $x_1_4 = {02 1f 23 1f 65 6f ?? 00 00 0a 10 00 02 6f ?? 00 00 0a 0a 06 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Injector_H_2147649690_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!H"
        threat_id = "2147649690"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 12 01 7b ?? 00 00 04 20 50 45 00 00 (40 11 00|33 0e) 12 00 7b ?? 00 00 04 20 4d 5a 00 00 (3b 01 00|2e 01) 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 12 01 7c ?? 00 00 04 7b ?? 00 00 04 20 00 30 00 00 1f 40 6f ?? 00 00 06 (3a 01 00|2d 01) 2a 11 09 12 04}  //weight: 1, accuracy: Low
        $x_1_3 = {11 0b 12 04 7b ?? 00 00 04 12 05 6f ?? 00 00 06 26 11 0c 12 04 7b ?? 00 00 04 6f ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_AI_2147650418_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.AI"
        threat_id = "2147650418"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {69 61 6d 66 69 72 73 74 31 00 67 66 68 72 74 75 00 67 65 74 5f 54 72 6f 65 73 74 65 72 00 54 72 6f 65 73 74 65 72 00 76 61 6c 75 65 00 68 64 74 79 68 74 68 74 00 69 6c 6c 75 69 6f 00 63 68 65 63 6b 6d 65 00 4f 75 74 41 74 74 72 69 62 75 74 65 00 66 73 65 64 72 34 65 68 31 00 6c 6b 6c 70 6b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_AL_2147652061_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.AL"
        threat_id = "2147652061"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 01 00 00 70 6f 0d 00 00 0a 80 04 00 00 04 7e 04 00 00 04 8e 69 80 03 00 00 04 06}  //weight: 1, accuracy: High
        $x_1_2 = {73 14 00 00 0a 26 18 17 1c 73 15 00 00 0a 0c 7e 16 00 00 0a 20 40 1f 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {11 04 11 05 9a 26 03 05 06 17 58 6f 24 00 00 0a 0c 08 15}  //weight: 1, accuracy: High
        $x_1_4 = "ekLxIHqvzkEatrmKOgJg" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_AQ_2147652430_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.AQ"
        threat_id = "2147652430"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 1e 00 00 0a 22 00 00 7a 44 28 1f 00 00 0a 5a 28 20 00 00 0a 22 00 00 80 3f 58 28 21 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {70 28 24 00 00 0a ?? 28 25 00 00 0a 72 ?? ?? ?? 70 28 22 00 00 0a 6f 23 00 00 0a ?? ?? ?? ?? 70 ?? 72 ?? ?? ?? 70 28 24 00 00 0a 18 16 15}  //weight: 1, accuracy: Low
        $x_1_3 = {11 28 28 00 00 0a 03 6f 29 00 00 0a ?? 02 02 8e b7 17 da 91 1f 70 61}  //weight: 1, accuracy: Low
        $x_1_4 = {03 6f 2a 00 00 0a 17 da 33}  //weight: 1, accuracy: High
        $x_1_5 = {74 1f 00 00 01 02 8e b7 18 da 17 d6 8d 1e 00 00 01 28 2b 00 00 0a}  //weight: 1, accuracy: High
        $x_1_6 = {09 54 00 45 00 4d 00 50 00 00 03 5c 00 00 09 2e 00 65 00 78 00 65 00 00}  //weight: 1, accuracy: High
        $x_1_7 = {4d 61 69 6e 00 64 65 63 72 79 70 74 00 6d 65 73 73 61 67 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule VirTool_MSIL_Injector_I_2147653113_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!I"
        threat_id = "2147653113"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 5c 08 09 58 20 f8 00 00 00 d3 58 1f 28 d3 11 ?? 5a 58 13}  //weight: 1, accuracy: Low
        $x_1_2 = {1f 3c 58 e0 4b 58 1f 78 58 e0 4b 58 0a 16 0b 2b 55}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_J_2147653994_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!J"
        threat_id = "2147653994"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 1f 5f 62 d2 20 00 01 00 00 5d 61}  //weight: 1, accuracy: High
        $x_1_2 = {2c 3d 7e 01 00 00 04 16 9a 19 8d 01 00 00 01 0a 06 16 7e 01 00 00 04 17 9a a2 06 17 7e 01 00 00 04 18 9a a2 06 18 1f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_BA_2147654204_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.BA"
        threat_id = "2147654204"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 20 82 fb 9d 4e 61 0b [0-5] 08 20 57 e1 0d 4a 61 0c 2b ?? 09 20 26 c1 bd 5b 61 0d 2b}  //weight: 1, accuracy: Low
        $x_1_2 = {20 eb 2b 9c 5b 0d 2b [0-9] ff ff 20 ef 6a 53 15 13 05}  //weight: 1, accuracy: Low
        $x_1_3 = {39 6f 00 66 00 66 00 73 00 65 00 74 00 20 00 2b 00 20 00 63 00 6f 00 75 00 6e 00 74 00 20 00 6f 00 75 00 74 00 20 00 6f 00 66 00 20 00 62 00 75 00 66 00 66 00 65 00 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_K_2147654290_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!K"
        threat_id = "2147654290"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 07 00 01 00}  //weight: 1, accuracy: High
        $x_1_2 = {11 12 20 b0 00 00 00 d3 58 11 15 28 ?? ?? ?? ?? 11 0e 1f 28 d3 58}  //weight: 1, accuracy: Low
        $x_1_3 = {11 15 11 0e 1f 50 d3 58 4b 20 00 30 00 00 1f 40 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_BS_2147656530_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.BS"
        threat_id = "2147656530"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {69 5d 91 03 06 03 8e 69 5d 91 61 02 06 17 58 02 8e 69 5d 91 59 20 00 01 00 00 58 0b 07 20 00 01 00}  //weight: 5, accuracy: High
        $x_1_2 = "SW5qZWN0UEU=" wide //weight: 1
        $x_1_3 = "c3ZjaG9zdA==" wide //weight: 1
        $x_1_4 = "KILLAMUVZ" wide //weight: 1
        $x_1_5 = "NoYou" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_N_2147656701_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!N"
        threat_id = "2147656701"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {79 72 6f 6d 65 4d 6c 61 75 74 72 69 56 65 74 69 72 57 74 4e 00 6e 6f 69 74 63 65 53 66 4f 77 65 69 56 70 61 6d 6e 55 74 4e}  //weight: 1, accuracy: High
        $x_1_2 = {00 70 75 74 72 61 74 73 00 7a 6e 75 52 00}  //weight: 1, accuracy: High
        $x_1_3 = {1f 1f 5f 62 09 61 08 58 61 d2 9c 09 17 58 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_MSIL_Injector_CO_2147658647_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!CO"
        threat_id = "2147658647"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 6a 65 63 74 69 6f 6e 00 41 70 70 4c 61 75 6e 63 68}  //weight: 1, accuracy: High
        $x_1_2 = {4d 65 6c 74 00 43 6f 70 69 61 7a 61}  //weight: 1, accuracy: High
        $x_1_3 = {58 6f 72 78 6f 72 78 6f 72 00}  //weight: 1, accuracy: High
        $x_1_4 = "DataProtector\\ClassLibrary1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Injector_CW_2147659368_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.CW"
        threat_id = "2147659368"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 06 11 07 9a 0c 08 6f ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 2c 67 08 6f ?? 00 00 0a 0d 09 13 08 16 13 09 2b 50}  //weight: 1, accuracy: Low
        $x_1_2 = "avfucker" ascii //weight: 1
        $x_1_3 = "invokmyass" ascii //weight: 1
        $x_1_4 = "myshittykey" wide //weight: 1
        $x_1_5 = "XOREncryptDecrypt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_DP_2147667863_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.DP"
        threat_id = "2147667863"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "crome1.exe" ascii //weight: 1
        $x_1_2 = "vfuck" ascii //weight: 1
        $x_1_3 = "invokmya" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_DW_2147673743_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.DW"
        threat_id = "2147673743"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {02 28 1e 00 00 06 17 8d ?? 00 00 01 0c 08 16 28 ?? 00 00 0a 6f ?? 00 00 0a a2 08 72 11 01 00 70 28 ?? 00 00 0a 72 29 01 00 70 28 ?? 00 00 0a 6f 14 00 00 06 26}  //weight: 2, accuracy: Low
        $x_1_2 = "get_Comite" ascii //weight: 1
        $x_1_3 = "Johny_Load" ascii //weight: 1
        $x_1_4 = "otoR.etimoC" wide //weight: 1
        $x_1_5 = "ExecBytes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_EC_2147678710_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.EC"
        threat_id = "2147678710"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6f 0e 00 00 0a 28 0f 00 00 0a 6f 10 00 00 0a 28 11 00 00 0a 17 8d 10 00 00 01 13 05 11 05 16 1f 7c 9d 11 05 6f 12 00 00 0a a2 09 28 13 00 00 0a 6f 14 00 00 0a 14 11 04 6f 15 00 00 0a}  //weight: 1, accuracy: High
        $x_1_2 = {20 5e 01 00 00 0a 28 16 00 00 0a 03 6f 17 00 00 0a 0b 16 0c 2b 31 02 08 8f 14 00 00 01 25 71 14 00 00 01 07 08 07 8e 69 5d 91 08 06 58 07 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 81 14 00 00 01 08 17 58 0c 08 02 8e 69 32 c9}  //weight: 1, accuracy: High
        $x_1_3 = "|1.0.2|" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_MSIL_Injector_ED_2147678801_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.ED"
        threat_id = "2147678801"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 1f 3c 28}  //weight: 1, accuracy: High
        $x_1_2 = {20 00 30 00 00 1f 40 6f ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_3 = {20 f8 00 00 00 d6 11 ?? 1f 28 d8 d6 11 ?? 16 1f 28 28}  //weight: 1, accuracy: Low
        $n_300_4 = "-Malwarebytes Scanner-" ascii //weight: -300
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_Q_2147682873_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!Q"
        threat_id = "2147682873"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 49 6e 6a 65 63 74 6f 72 20 4d 73 70 20 56 31 2e ?? 2e 65 78 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 61 00 6c 00 46 00 69 00 6c 00 65 00 6e 00 61 00 6d 00 65 00 00 00 49 00 6e 00 6a 00 65 00 63 00 74 00 6f 00 72 00 20 00 4d 00 73 00 70 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_EI_2147683031_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.EI"
        threat_id = "2147683031"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 71 30 33 4e 64 6f 6a 39 38 79 43 58 32 56 6d 71 30 68 6e 36 4a 75 33 73 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 68 6b 6a 4f 32 33 37 36 47 73 35 36 39 67 58 32 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 42 6f 74 6f 6d 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_EK_2147684322_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.EK"
        threat_id = "2147684322"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d6 20 ff 00 00 00 5f 91 06 09 91 61 9c 09 17 d6}  //weight: 1, accuracy: High
        $x_1_2 = {00 41 00 44 49 00 4b 65 79 62 6f 61 72 64 48 6f 6f 6b 00 44 43 49 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_EK_2147684322_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.EK"
        threat_id = "2147684322"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {49 6e 6a 65 63 74 4e 65 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {49 6e 6a 65 63 74 00 44 6e 45 00}  //weight: 1, accuracy: High
        $x_1_3 = "ping -n 1 -w 3000 1.1.1.1" wide //weight: 1
        $x_1_4 = "/C {0} \"{4}\" & {1} & {2} \"{5}\" & {3} \"{5}\"" wide //weight: 1
        $x_1_5 = "/c reg add \"HKCU\\Software\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\" /f /v shell /t REG_SZ /d explorer.exe,\"" wide //weight: 1
        $x_1_6 = {13 13 02 11 04 20 f8 00 00 00 58 11 12 1f 28 5a 58 11 13 16 1f 28 28}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_EM_2147684749_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.EM"
        threat_id = "2147684749"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 17 58 10 00 02 17 59 03 61 10 00 02 2a 00}  //weight: 1, accuracy: High
        $x_1_2 = {1b 0a 16 0b 2b 53 16 0c 2b 45 06 08 06 08 91 03 08 03 8e 69 5d 91 28}  //weight: 1, accuracy: High
        $x_1_3 = {06 11 04 49 20 4d 5a 00 00 2e 02 16 2a 11 04 1f 3c d3 58 4a 13}  //weight: 1, accuracy: High
        $x_1_4 = {00 43 6c 61 5a 78 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 4d 65 6d 65 78 00}  //weight: 1, accuracy: High
        $x_1_6 = {0e 41 64 6f 62 65 20 53 79 73 74 d0 b5 6d 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {0e 41 64 6f 62 d0 b5 20 52 d0 b5 61 64 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_EP_2147687108_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.EP"
        threat_id = "2147687108"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 03 07 03 8e b7 5d 91 61 02 07 17 d6 02 8e}  //weight: 1, accuracy: High
        $x_1_2 = {0b 07 08 da 20 f4 01 00 00 6a fe 04 0d 09 2c 04 17 0a 2b 03 00 16 0a 00 06 2a}  //weight: 1, accuracy: High
        $x_1_3 = {4f 00 4c 00 4c 00 59 00 44 00 42 00 47 00 00 ?? 53 00 61 00 6e 00 64 00 42 00 6f 00 78 00 69 00 65 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 00 42 00 41 00 4d 00 53 00 43 00 48 00 45 00 44 00 55 00 4c 00 45 00 52 00 00 ?? 76 00 6d 00 77 00 61 00 72 00 65 00 00 ?? 56 00 4d 00 57 00 41 00 52 00 45 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {02 11 23 1f 57 28 ?? ?? ?? ?? 72 ?? ?? ?? ?? 28}  //weight: 1, accuracy: Low
        $x_1_6 = {23 72 00 69 00 74 00 65 00 50 00 72 00 6f 00 63 00 65 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 00 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_EQ_2147687176_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.EQ"
        threat_id = "2147687176"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\vbc.exe" ascii //weight: 1
        $x_1_2 = "C:\\Windows\\Microsoft.NET\\Framework\\v2.0.50727\\csc.exe" wide //weight: 1
        $x_1_3 = "RW50cnlQb2ludA==" wide //weight: 1
        $x_1_4 = {06 09 02 08 17 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 61 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 0a 00 08 17 58 b5 0c 08 11 04 31 d5}  //weight: 1, accuracy: Low
        $x_1_5 = {2b 19 08 09 16 11 05 6f ?? ?? ?? ?? 00 07 09 16 09 8e b7 6f ?? ?? ?? ?? 13 05 00 11 05 16 30 e2}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Injector_ES_2147688127_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.ES"
        threat_id = "2147688127"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 20 00 01 00 00 5a 13 05 11 06 17 58 13 06 11 06 11 04 fe 04 13 08 11 08 2d e4 09 11 05 07 11 04 91 5a 58 0d 00 11 04 17 58 13 04 11 04 1a fe 04 13 08 11 08}  //weight: 1, accuracy: High
        $x_1_2 = {02 7b 03 00 00 04 06 02 7b 03 00 00 04 06 91 02 7b 04 00 00 04 07 91 61 d2 9c 07 17 58 0b 07 02 7b 04 00 00 04 8e 69 fe 04 0c 08 2d d3 06 17 58 0a 06 02 7b 03 00 00 04 8e 69 fe 04 0c 08 2d bc 2a}  //weight: 1, accuracy: High
        $x_1_3 = {02 22 00 00 c0 40 22 00 00 50 41 73 ?? 00 00 0a 28 ?? 00 00 0a 00 02 17 28 ?? 00 00 0a 00 02 20 e9 01 00 00 20 c7 00 00 00 73 ?? 00 00 0a 28 ?? 00 00 0a 00 02 72 01 00 00 70 28 ?? 00 00 0a 00 02 72 01 00 00 70 6f ?? 00 00 0a 00 02 02 fe 06 07 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_EV_2147688520_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.EV"
        threat_id = "2147688520"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 17 11 08 11 07 11 08 11 07 91 11 05 11 09 91 61 d2 9c 11 09 17 58 13 09 11 09 11 05 8e 69 fe 04 13 0b 11 0b 2d db}  //weight: 1, accuracy: High
        $x_1_2 = {2b 23 11 06 08 11 07 91 6c 23 00 00 00 00 00 00 70 40}  //weight: 1, accuracy: High
        $x_1_3 = {15 53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 01 00 00 00 04 44 61 74 61 07 02 02 00 00 00 09 03 00 00 00 0f 03 00 00 00 ?? ?? ?? ?? 02 89 50 4e 47}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_EW_2147688990_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.EW"
        threat_id = "2147688990"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 6e 74 69 53 61 6e 64 69 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {4d 6f 6e 69 74 6f 72 49 6e 6a 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {56 4d 52 75 6e 6e 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_4 = {52 75 6e 50 45 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 65 6d 6f 76 65 5f 50 6f 6e 67 00}  //weight: 1, accuracy: High
        $x_1_6 = ":Zone.Identifier" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_FA_2147692357_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.FA"
        threat_id = "2147692357"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0c 2b 0f 06 07 06 07 91 03 08 91 61 d2 9c 08 17 58 0c 08 03 8e 69 32 eb}  //weight: 1, accuracy: High
        $x_1_2 = {1f 27 9a 13 ?? 11 ?? 14 17 8d 01 00 00 01 13 ?? 11 ?? 16 11 04 a2 11 ?? 6f ?? 00 00 0a 74 ?? 00 00 01}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_FB_2147692769_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.FB"
        threat_id = "2147692769"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\":ZONE.identifier" wide //weight: 1
        $x_1_2 = "-keyhide" wide //weight: 1
        $x_1_3 = "-avkill" wide //weight: 1
        $x_1_4 = "-WPE PRO" wide //weight: 1
        $x_1_5 = "XFxTeXN0ZW0zMlxcc3ZjaG9zdC5leGU=" wide //weight: 1
        $x_1_6 = {57 00 69 00 6e 00 6c 00 6f 00 67 00 6f 00 6e 00 ?? ?? 53 00 68 00 65 00 6c 00 6c 00 ?? ?? 65 00 78 00 70 00 6c 00 6f 00 72 00 65 00 72 00 2e 00 65 00 78 00 65 00 2c 00}  //weight: 1, accuracy: Low
        $x_1_7 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule VirTool_MSIL_Injector_FW_2147694459_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.FW"
        threat_id = "2147694459"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "H55H8BHECH83HE4HF8H51H53H33HC0H56H57H33HD2HC6H44H24H" ascii //weight: 2
        $x_1_2 = {16 1b 9c 11 06 17 20 9b 00 00 00 9c 11 06 18 20 f2 00 00 00 9c 11 06 19 1f 37 9c}  //weight: 1, accuracy: High
        $x_1_3 = {16 1b 9c 07 17 20 9b 00 00 00 9c 07 18 20 f2 00 00 00 9c 07 19 1f 37 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_FX_2147694470_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.FX"
        threat_id = "2147694470"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 0f 02 06 02 06 91 03 07 91 61 d2 9c 07 17 58 0b 07 03 8e 69 32 eb}  //weight: 1, accuracy: High
        $x_1_2 = {1f 23 9d 11 07 6f ?? ?? ?? ?? 0a 06 8e 69 8d ?? ?? ?? ?? 0b 16 0c 2b 0f 07 08 06 08 9a}  //weight: 1, accuracy: Low
        $x_1_3 = {33 2a 16 13 04 2b 06 11 04 17 58 13 04 11 04 09 8e 69 2f 0f 09 11 04 9a 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_FY_2147694592_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.FY"
        threat_id = "2147694592"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b 0f 06 07 06 07 91 03 08 91 61 d2 9c 08 17 58 0c 08 03 8e 69 32 eb}  //weight: 1, accuracy: High
        $x_1_2 = {32 e8 12 02 7e ?? ?? ?? ?? 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? 13 04 11 04 1f 27}  //weight: 1, accuracy: Low
        $x_1_3 = {32 e6 06 17 58 0a 06 02 50 8e 69 32 d7}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_GA_2147696528_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GA"
        threat_id = "2147696528"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {7e 0b 00 00 04 07 7e 0b 00 00 04 07 91 7e 04 00 00 04 07 7e 04 00 00 04 8e 69 5d 91 61 d2 9c 07 17 58 0b}  //weight: 1, accuracy: High
        $x_1_2 = {7e 0b 00 00 04 07 7e 0b 00 00 04 07 91 7e 04 00 00 04 08 91 06 1f 1f 5f 62 08 61 07 58 61 d2 9c 08 17 58 0c}  //weight: 1, accuracy: High
        $x_1_3 = "wzxscuYT.pLegvoHe" ascii //weight: 1
        $x_1_4 = {00 72 6f 73 74 61 6d 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Injector_GC_2147697269_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GC"
        threat_id = "2147697269"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {61 25 0a 19 5e 45 03 00 00 00 e0 ff ff ff 02 00 00 00 12 00 00 00 2b 10 00 06 20 ?? ?? ?? ?? 5a 20 ?? ?? ?? ?? 61 2b d3}  //weight: 1, accuracy: Low
        $x_1_2 = "#4=~q4iBbQ}\\]\\] 3Q`Qm\\[rh\\*?%" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_GD_2147697295_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GD"
        threat_id = "2147697295"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NoIkarus + Injections\\Msi\\Msi" ascii //weight: 1
        $x_1_2 = "Windows\\EFS.exe" ascii //weight: 1
        $x_1_3 = "Sefule.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_GE_2147697359_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GE"
        threat_id = "2147697359"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4c 4f 41 44 45 52 2e 72 65 73 6f 75 72 63 65 73 00 00 00 0d 4c 00 4f 00 41 00 44 00 45 00 52 00 00 0b 49 00 4d 00 41 00 47 00 45 00 00 07 4b 00 45 00 59 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 01 00 00 00 d0 02 00 00 02 28 03 00 00 0a 6f 04 00 00 0a 73 05 00 00 0a 0a 06 72 0f 00 00 70 6f 06 00 00 0a 74 04 00 00 01 0b 07 28 04 00 00 06 0c 73 07 00 00 0a}  //weight: 1, accuracy: High
        $x_1_3 = {08 09 9a 0a 06 6f 11 00 00 0a 72 6f 00 00 70 28 12 00 00 0a 16 fe 01 13 04 11 04 2d 54 06 6f 13 00 00 0a 8e 69 17 fe 01 16 fe 01 13 04 11 04 2d 40 06 6f 13 00 00 0a 16}  //weight: 1, accuracy: High
        $x_1_4 = {7e 01 00 00 04 8d 08 00 00 01 0a 16 0b 16 0c 38 bc 00 00 00 16 0d 38 91 00 00 00 00 02 09 08 6f 15 00 00 0a 13 04 16 13 05 2b 63 11 05 13 07 11 07 45 04 00 00 00 02 00 00 00 12 00 00 00 22 00 00 00 32 00 00 00 2b 40 06 07 25 17 58 0b 12 04 28 16 00 00 0a 9c 2b 30}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Injector_GF_2147697360_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GF"
        threat_id = "2147697360"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {4c 61 79 73 4f 72 65 2e 65 78 65 00}  //weight: 5, accuracy: High
        $x_1_2 = {16 2d 64 20 c8 33 97 78 20 10 76 1b 7a 25 2c 45 61 25 2b 55 19 5e 16 2d ef 45 03 00 00 00 3d 00 00 00 02 00 00 00 d6 ff ff ff 2b 3b 2b 3e 7b 0d 00 00 04 2b 3a}  //weight: 1, accuracy: High
        $x_1_3 = {20 13 a5 24 ac 20 db 93 80 f3 61 25 38 81 01 00 00 1f 0d 5e 45 0d 00 00 00 5d 00 00 00 de 00 00 00 c1 00 00 00 b3 ff ff ff 0c 01 00 00 ae 00 00 00 35 00 00 00 20 01 00 00 91 00 00 00 43 01 00 00 05 00 00 00 f9 00 00 00 73 00 00 00 38 3e 01 00 00 1d 39 0b 01 00 00 38 3c 01 00 00 2c 08 20 72 7c c4 98 25 2b}  //weight: 1, accuracy: High
        $x_1_4 = {16 2d 05 19 25 2c 2e 5e 45 03 00 00 00 d9 ff ff ff 02 00 00 00 1f 00 00 00 2b 1d 2b 1f 80 15 00 00 04 16 2d cd 2b 18 20 56 c9 a7 14 25 2c cd 5a 20 c1 18 72 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_GH_2147697775_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GH"
        threat_id = "2147697775"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {11 05 13 07 11 07 45 04 00 00 00 02 00 00 00 12 00 00 00 22 00 00 00 32 00 00 00 2b 40}  //weight: 1, accuracy: High
        $x_1_2 = {11 04 8e 69 58 28 01 00 00 2b 00 11 04 16 08 08 8e 69 11 04 8e 69 59 11 04 8e 69 28}  //weight: 1, accuracy: High
        $x_1_3 = "LOADER" wide //weight: 1
        $x_1_4 = "DATASIZE" wide //weight: 1
        $x_1_5 = "REDAOL" wide //weight: 1
        $x_1_6 = "EZISATAD" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_GI_2147705650_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GI"
        threat_id = "2147705650"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 77 61 65 67 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {70 66 4d 52 71 4f 77 51 62 48 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 66 4d 52 71 4f 77 51 62 48 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {7e 12 00 00 04 0c 1c 0b 07 45 07 00 00 00 27 00 00 00 0a 00 00 00 27 00 00 00 2e 00 00 00 27 00 00 00 1c 00 00 00 00 00 00 00 03 2c 04 17 0b 2b d7 18 2b fa 02 7b 0e 00 00 04 2c 04 1b 0b 2b c8 08 1f 15 91 2b f7 02 7b 0e 00 00 04 6f 1b 00 00 0a 02 03 28 1c 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_5 = {7e 0a 00 00 04 0c 1b 0b 07 45 07 00 00 00 3d 00 00 00 10 00 00 00 2d 00 00 00 3d 00 00 00 10 00 00 00 00 00 00 00 2d 00 00 00 03 2c 0a 08 20 91 00 00 00 91 0b 2b d1 19 2b fa 02 7c 10 00 00 04 7b 13 00 00 04 2c 04 1c 0b 2b bd 08 20 e1 00 00 00 91 1f 4e 59 2b f1 02 7c 10 00 00 04 7b 13 00 00 04 6f 1a 00 00 0a 02 03 28 1b 00 00 0a 2a}  //weight: 1, accuracy: High
        $x_1_6 = {06 02 17 20 ?? 01 00 00 20 ?? 01 00 00 28 0b 00 00 2b 02 16 20 ?? 00 00 00 20 ?? 00 00 00 28 0c 00 00 2b 02 16 28 ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_GJ_2147705651_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GJ"
        threat_id = "2147705651"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {64 6f 63 69 6e 68 6f 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 61 6e 74 61 73 6d 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {66 6f 73 67 61 00}  //weight: 1, accuracy: High
        $x_1_4 = {78 69 6d 75 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 73 61 6f 6a 6f 61 6f 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_6 = {62 75 72 65 61 6c 00}  //weight: 1, accuracy: High
        $x_1_7 = {44 72 65 6e 61 2e 73 61 6f 70 65 64 72 6f 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_GJ_2147705651_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GJ"
        threat_id = "2147705651"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2e 73 61 6f 6a 6f 61 6f 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 6f 73 67 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {78 69 6d 75 00}  //weight: 1, accuracy: High
        $x_1_4 = {62 61 62 79 6c 69 73 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "##$$$OPBRPXXPXPAAPAPAPAa990000x0x0xx" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_GL_2147706005_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GL"
        threat_id = "2147706005"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {4f 59 66 63 73 4c 4d 72 74 44 6e 46 46 6d 66 4d 72 44 2e 63 4b 41 6f 34 31 77 63 65 50 61 4a 42 4c 4d 51 72 77 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = {6b 32 77 57 4d 50 4f 36 64 78 35 4a 66 79 6e 58 49 72 2e 71 55 6c 79 39 75 4d 64 65 64 74 56 67 36 48 39 63 31 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 52 33 6e 62 66 38 64 51 70 32 66 65 4c 6d 6b 33 31 2e 6c 53 66 67 41 70 61 74 6b 64 78 73 56 63 47 63 72 6b 74 6f 46 64 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
        $x_2_4 = "cremosso.Properties.Resources" wide //weight: 2
        $x_1_5 = {2b 02 26 16 20 17 00 00 00 38 cf 00 00 00 d0 03 00 00 02 28 02 00 00 0a 6f 03 00 00 0a 20 00 00 00 00 28 99 00 00 06 17 17 8d 01 00 00 01 25 16 28 11 00 00 06 a2 28 12 00 00 06 74 04 00 00 01 13 04 20 10 00 00 00 38 91 00 00 00 38 9b 02 00 00 11 0c 11 0d 9a 13 0e 20 1a 00 00 00 17 3a 7a 00 00 00 26 11 0a 17 58 13 0a}  //weight: 1, accuracy: High
        $x_1_6 = {2b 02 26 16 20 06 00 00 00 38 c0 00 00 00 02 20 24 01 00 00 20 0d 01 00 00 73 08 00 00 0a 28 09 00 00 0a 20 04 00 00 00 38 a1 00 00 00 02 28 16 00 00 06 20 03 00 00 00 38 91 00 00 00 02 22 00 00 c0 40 22 00 00 50 41 73 0a 00 00 0a 28 17 00 00 06 28 0a 00 00 06 28 09 00 00 06 39 a3 00 00 00 26 20 01 00 00 00 38 62 00 00 00 02 02 fe 06 04 00 00 06 73 0b 00 00 0a 28 1b 00 00 06 20 00 00 00 00 16 39 45 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_S_2147706053_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!S"
        threat_id = "2147706053"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "$9a971fa3-2888-420b-a460-794e0736706a" ascii //weight: 2
        $x_2_2 = "CallByName" ascii //weight: 2
        $x_1_3 = "brico.exe" ascii //weight: 1
        $x_1_4 = "tocat.exe" ascii //weight: 1
        $x_1_5 = "cloloir.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_V_2147706087_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!V"
        threat_id = "2147706087"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "LozCw\\BSr" ascii //weight: 1
        $x_1_2 = "SILlzCwXBSr" ascii //weight: 1
        $x_1_3 = "GetTypes" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_GM_2147706264_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GM"
        threat_id = "2147706264"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 2b 23 02 06 02 06 91 05 06 04 5d 91 06 1b 58 05 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 06 17 58 0a 06 02 8e 69 32 d7 02 2a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_GM_2147706264_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GM"
        threat_id = "2147706264"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 09 07 09 91 06 09 08 6f ?? 00 00 0a 5d 91 09 1b 58 06 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 09 17 58 0d 09 07 8e 69 32 d2 07 28 04 00 00 06 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {02 06 02 06 91 03 06 04 6f ?? 00 00 0a 5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 06 17 58 0a 06 02 8e 69 32 d2}  //weight: 1, accuracy: Low
        $x_1_3 = {07 08 07 08 91 02 08 72 ?? 00 00 70 6f ?? 00 00 0a 5d 91 08 1b 58 02 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c 08 17 58 0c 08 07 8e 69 32 ac}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_MSIL_Injector_GN_2147706335_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GN"
        threat_id = "2147706335"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hSystem.Drawing.Bitmap, System.Drawing, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3aPADPAD" ascii //weight: 1
        $x_1_2 = "aJK0fI8N" wide //weight: 1
        $x_1_3 = "aUTOUM6NacH5" wide //weight: 1
        $x_1_4 = "aYdBrIvPNs" wide //weight: 1
        $x_1_5 = "azb7IUXz2aQa" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_GO_2147706421_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GO"
        threat_id = "2147706421"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 72 6f 69 61 00}  //weight: 1, accuracy: High
        $x_1_2 = {66 6f 73 67 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 73 61 6f 6a 6f 61 6f 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "pedrokqsu" wide //weight: 1
        $x_1_5 = "4a7db6b1-7b83-46dc-a2f2-ee34a4703530" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_X_2147706449_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.gen!X"
        threat_id = "2147706449"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AssemblyFlagsAttribute" ascii //weight: 1
        $x_1_2 = "AssemblyNameFlags" ascii //weight: 1
        $x_1_3 = "ClassMain" wide //weight: 1
        $x_2_4 = "c:\\Users\\Administrator\\Desktop\\Cryptex\\" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_GP_2147706527_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GP"
        threat_id = "2147706527"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2e 73 61 6f 6a 6f 73 65 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 10, accuracy: High
        $x_10_2 = {74 72 6f 69 61 00}  //weight: 10, accuracy: High
        $x_1_3 = {24 33 39 63 63 66 38 62 61 2d 66 62 38 34 2d 34 32 62 35 2d 61 37 64 62 2d 65 62 30 32 61 36 32 61 38 36 36 36 00}  //weight: 1, accuracy: High
        $x_1_4 = {24 37 61 62 32 64 61 30 66 2d 36 31 34 31 2d 34 39 63 30 2d 38 36 31 61 2d 34 66 63 61 38 62 61 61 66 61 62 62 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_GQ_2147706528_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GQ"
        threat_id = "2147706528"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 35 37 36 31 36 61 32 37 2d 63 64 33 37 2d 34 31 38 38 2d 62 30 33 39 2d 65 31 31 36 33 39 34 38 38 34 62 36 00}  //weight: 1, accuracy: High
        $x_1_2 = {43 6f 6e 74 6f 73 73 61 20 53 75 69 74 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {62 61 72 69 63 6d 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {43 6f 6e 74 6f 73 73 61 20 43 6f 72 70 6f 72 61 74 69 6f 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_GR_2147706665_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GR"
        threat_id = "2147706665"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 36 34 64 65 39 30 30 65 2d 63 37 38 63 2d 34 33 39 32 2d 62 62 66 38 2d 35 63 63 38 61 36 66 37 38 32 31 37 00}  //weight: 1, accuracy: High
        $x_1_2 = {72 6c 63 73 79 73 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = {70 00 65 00 73 00 74 00 69 00 70 00 69 00 63 00 00 00}  //weight: 1, accuracy: High
        $x_1_4 = {72 6c 63 73 79 73 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {64 65 73 65 6e 20 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_GW_2147706802_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GW"
        threat_id = "2147706802"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {24 30 35 39 39 61 35 34 39 2d 61 31 62 36 2d 34 34 62 35 2d 39 39 34 34 2d 33 32 66 63 65 31 66 33 63 31 64 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {65 00 74 00 75 00 66 00 67 00 64 00 7a 00 68 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {3c 64 7a 72 74 68 7a 6d 78 3e 00}  //weight: 1, accuracy: High
        $x_1_4 = {65 74 75 66 67 64 7a 68 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
        $x_1_5 = {70 6c 61 70 75 6d 61 20 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_GY_2147706878_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GY"
        threat_id = "2147706878"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {32 af 7e 1d 00 00 0a 13 06 7e 1d 00 00 0a 08 8e 69 20 00 30 00 00 1f 40 28 0a 00 00 06 13 06 08 16 11 06 08 8e 69 28 20 00 00 0a 11 06 d0 05 00 00 02}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_GX_2147706884_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.GX"
        threat_id = "2147706884"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {70 6f 70 69 63 20 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
        $x_1_2 = "cm90YXRlJA==" wide //weight: 1
        $x_1_3 = {1f 11 91 1f 4d 59 13 05 2b b4 03 04 61 1f 2b 59 06 61 45 01 00 00 00 05 00 00 00 19 13 05 2b 9e 1e 2b f9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_HA_2147707000_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HA"
        threat_id = "2147707000"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".PE" wide //weight: 1
        $x_1_2 = "sector" wide //weight: 1
        $x_1_3 = "saojoao.Properties." wide //weight: 1
        $x_1_4 = "saojose.Properties." wide //weight: 1
        $x_1_5 = {11 05 91 08 61}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_HB_2147707053_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HB"
        threat_id = "2147707053"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "_injectionPath" ascii //weight: 1
        $x_1_2 = {4d 6f 6e 69 74 6f 72 49 6e 6a 65 63 74 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 43 00 72 00 65 00 64 00 65 00 6e 00 74 00 69 00 61 00 6c 00 73 00 5c 00 ?? ?? 73 00 6d 00 74 00 70 00 63 00 6f 00 2e 00 65 00 78 00 65 00 ?? ?? 73 00 63 00 73 00 69 00 73 00 76 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {75 00 6e 00 63 00 68 00 2e 00 65 00 78 00 65 00 ?? ?? 75 00 66 00 65 00 71 00 73 00 65 00 64 00 75 00 71 00 67 00}  //weight: 1, accuracy: Low
        $x_1_5 = "cheltochel" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_HD_2147707191_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HD"
        threat_id = "2147707191"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {66 20 d7 b4 f1 f1 5a 66 20 e7 86 0f 85 5a 20 52 a0 23 ac 66 20 fa 80 49 c3 20 75 96 b1 a2 20 68 a3 0f 5c 59}  //weight: 1, accuracy: High
        $x_1_2 = {61 58 20 44 0c 00 00 28 18 00 00 06 5a 65 65 20 48 0c 00 00 28 18 00 00 06 58 66 66 59 58}  //weight: 1, accuracy: High
        $x_1_3 = {24 31 33 61 37 64 35 32 35 2d 65 35 32 34 2d 34 35 34 37 2d 61 66 39 31 2d 66 61 61 39 61 61 34 62 38 37 64 37 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 7a 75 72 61 4d 61 6e 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_MSIL_Injector_HG_2147707475_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HG"
        threat_id = "2147707475"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {69 17 da 13 ?? 16 13 ?? 2b ?? ?? 11 ?? 02 11 ?? 91 ?? 61 [0-4] 91 61 9c ?? 28}  //weight: 1, accuracy: Low
        $x_1_2 = "KISSMADICK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_HK_2147707682_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HK"
        threat_id = "2147707682"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8e 69 5d 91 61 28}  //weight: 1, accuracy: High
        $x_1_2 = {08 20 9c 00 00 00 93 20 be 77 00 00 59 13 08 38}  //weight: 1, accuracy: High
        $x_1_3 = {1f 1f 5f 1f 1f 5f 1f 1f 5f 1f 1f 5f 62 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_HL_2147707741_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HL"
        threat_id = "2147707741"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 00 0e 00 00 8d 05 00 00 01 13 06 11 06 16 1f ?? 9c 11 06 17 1f 16 9c 11 06 18 20 d5 00 00 00 9c 11 06 19 1f 54 9c 11 06 1a 1f 6b 9c 11 06 1b 1f 6a 9c 11 06 1c 1f 4a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_HL_2147707741_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HL"
        threat_id = "2147707741"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 61 9c 11 ?? 17 58 13 ?? 11 ?? 11 ?? 31}  //weight: 1, accuracy: Low
        $x_1_2 = {20 18 01 00 00 14 14 17 8d}  //weight: 1, accuracy: High
        $x_1_3 = {91 61 9c 08 17 58 0c 08 11 ?? 31}  //weight: 1, accuracy: Low
        $x_1_4 = {1f 5c 6a 73 ?? ?? ?? ?? 13 ?? 17 2d ?? 20 d0 0f 00 00 0b}  //weight: 1, accuracy: Low
        $x_1_5 = {20 8d 7f ee 00 6a 73 ?? ?? ?? ?? 13 ?? 16 2d}  //weight: 1, accuracy: Low
        $x_1_6 = {20 08 01 00 00 8c}  //weight: 1, accuracy: High
        $x_1_7 = {1f 64 fe 04 5f 2c}  //weight: 1, accuracy: High
        $x_1_8 = {91 61 9c 06 [0-16] 58 4a 31}  //weight: 1, accuracy: Low
        $x_1_9 = "Failed with win32 error code {0}" wide //weight: 1
        $x_1_10 = "Parent Proc. ID: {0}, Parent Proc. name: {1}" wide //weight: 1
        $n_100_11 = "xpecto" wide //weight: -100
        $n_100_12 = "eAgenturNET" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (3 of ($x*))
}

rule VirTool_MSIL_Injector_HW_2147707814_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HW"
        threat_id = "2147707814"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c}  //weight: 1, accuracy: High
        $x_1_2 = {20 b3 2d 00 00 0b 07 20 b3 2d 00 00 33 06 06 28}  //weight: 1, accuracy: High
        $x_1_3 = {53 65 63 6f 6e 64 53 65 6d 65 73 74 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_HX_2147707924_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HX"
        threat_id = "2147707924"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 6e 16 28 ?? ?? ?? ?? 6a 5f 69 95 61}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_HY_2147707925_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.HY"
        threat_id = "2147707925"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rndmkey" ascii //weight: 1
        $x_1_2 = "Scribe" ascii //weight: 1
        $x_1_3 = "Botkill" ascii //weight: 1
        $x_1_4 = "KillAndDelete" ascii //weight: 1
        $x_1_5 = "EraseS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_IB_2147707980_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IB"
        threat_id = "2147707980"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 00 6e 00 61 00 62 00 6c 00 65 00 66 00 61 00 6b 00 65 00 ?? ?? 65 00 6e 00 61 00 62 00 6c 00 65 00 73 00 74 00 61 00 72 00 74 00 75 00 70 00 ?? ?? 66 00 61 00 6b 00 65 00 6d 00 65 00 73 00 73 00 61 00 67 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = {41 00 6e 00 61 00 6c 00 79 00 7a 00 65 00 72 00 ?? ?? 53 00 62 00 69 00 65 00 53 00 76 00 63 00 ?? ?? 61 00 6e 00 75 00 62 00 69 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {7b 00 30 00 7d 00 2e 00 65 00 78 00 65 00 ?? ?? 2a 00 2e 00 65 00 78 00 65 00 ?? ?? 72 00 65 00 67 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {5c 00 52 00 75 00 6e 00 22 00 20 00 2f 00 66 00 20 00 2f 00 76 00 20 00 22 00 ?? ?? 22 00 20 00 2f 00 74 00 20 00 52 00 45 00 47 00 5f 00 53 00 5a 00 20 00 2f 00 64 00}  //weight: 1, accuracy: Low
        $x_1_5 = "d0Y0cFtAAwUCNAoIAwAeAw==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_IF_2147708068_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IF"
        threat_id = "2147708068"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {17 58 0c 08 07 61 0c 06 16 07}  //weight: 10, accuracy: High
        $x_10_2 = {00 4c 6f 61 64 6d 65 00 52 65 67 6d 65 00 57 61 69 74 4f 6e 65 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 50 65 72 73 69 73 74 65 6e 63 65 00 46 69 6c 65 70 65 72 73 69 73 74 65 6e 63 65 00}  //weight: 10, accuracy: High
        $x_1_4 = {00 4c 6f 61 64 6d 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 52 65 67 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_IG_2147708132_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IG"
        threat_id = "2147708132"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {02 20 4c c2 34 35 61 03 61 0a}  //weight: 1, accuracy: High
        $x_1_2 = "d60e480c-43bd-4ab7-8da0-3ffaa1ad5c24" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_IH_2147708133_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IH"
        threat_id = "2147708133"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {91 61 9c 11 ?? 17 58 13 ?? 11 ?? 11 ?? 31}  //weight: 1, accuracy: Low
        $x_1_2 = {67 65 74 5f 42 69 73 71 75 65 00 67 65 74 5f 4d 61 67 65 6e 74 61 00 67 65 74 5f 4c 69 6d 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_IL_2147708542_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IL"
        threat_id = "2147708542"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6c 65 76 65 72 61 67 65 2e 65 78 65 00 6c 65 76 65 72 61 67 65 00}  //weight: 1, accuracy: High
        $x_1_2 = {47 5a 69 70 53 74 72 65 61 6d 00 53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {44 6f 63 75 6d 65 6e 74 20 53 63 61 6e 6e 65 72 00}  //weight: 1, accuracy: High
        $x_1_4 = {13 6c 65 76 65 72 61 67 65 2e 50 72 6f 70 65 72 74 69 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_IM_2147708611_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IM"
        threat_id = "2147708611"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {46 53 00 4f 62 6a 65 63 74 00 42 00 43 00 54 00}  //weight: 1, accuracy: High
        $x_1_2 = {42 61 73 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00 46 6f 72 6d 31 00}  //weight: 1, accuracy: High
        $x_1_3 = ".x{0}" wide //weight: 1
        $x_1_4 = "Adversus solem ne loquitor!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_II_2147708717_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.II!bit"
        threat_id = "2147708717"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 44 65 63 72 79 70 74 6f 72 00 54 72 61 6e 73 66 6f 72 6d 46 69 6e 61 6c 42 6c 6f 63 6b}  //weight: 1, accuracy: High
        $x_1_2 = {53 00 79 00 73 00 74 00 65 00 6d 00 2e 00 52 00 65 00 66 00 6c 00 65 00 63 00 74 00 69 00 6f 00 6e 00 2e 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 ?? ?? 45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {06 07 02 02 8e 69 17 59 07 59 91 9c 07 17 58 0b 07 06 8e 69 fe 04 0d 09 2d e6 06 0c 2b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_IN_2147708847_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IN"
        threat_id = "2147708847"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 61 72 70 61 74 69 2e 65 78 65 00 43 61 72 70 61 74 69 00}  //weight: 1, accuracy: High
        $x_1_2 = {79 6f 75 6d 65 68 69 6d 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 3c 4d 6f 64 75 6c 65 3e 00}  //weight: 1, accuracy: High
        $x_1_3 = {47 5a 69 70 53 74 72 65 61 6d 00 53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 00}  //weight: 1, accuracy: High
        $x_1_4 = {1e 2c 3d 20 a0 01 00 00 8d 01 00 00 01 25 d0 31 00 00 04 18 2d 2b 26 26 80 32 00 00 04 18 2c 20 20 44 01 00 00 25 2c e0 25 2c dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule VirTool_MSIL_Injector_IQ_2147709018_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IQ"
        threat_id = "2147709018"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 91 61 d2 9c 07 17 58 0b 07 7e ?? ?? ?? ?? 8e 69 fe 04 13 04 11 04 2d dd 06}  //weight: 1, accuracy: Low
        $x_1_2 = {2b 1c 06 23 00 00 00 00 00 00 70 40 07 6c 28 ?? ?? ?? ?? 69 02 07 91 5a 58 0a 07 17 58 0b 07 1a fe 04 0d 09 2d dc}  //weight: 1, accuracy: Low
        $x_1_3 = {24 24 6d 65 74 68 6f 64 30 78 36 30 30 30 30 31 39 2d 33 00 49 6e 74 33 32 00 43 6f 6c 6f 72 00 67 65 74 5f 42 00 67 65 74 5f 52 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_MSIL_Injector_IX_2147710752_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IX!bit"
        threat_id = "2147710752"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 00 0a 91 61 9c 11 ?? 17 58 13 ?? 11 ?? 11 ?? 31}  //weight: 1, accuracy: Low
        $x_1_2 = {09 4c 00 6f 00 61 00 64 00 00 15 45 00 6e 00 74 00 72 00 79 00 70 00 6f 00 69 00 6e 00 74 00 00}  //weight: 1, accuracy: High
        $x_1_3 = {2e 64 6c 6c 00 53 74 72 43 6d 70 4c 6f 67 69 63 61 6c 57 00 73 31 00 73 32 00 73 68 6c 77 61 70 69 2e 64 6c 6c 00 5f 41 36 [0-80] 5f 41 37}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_IX_2147711077_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IX"
        threat_id = "2147711077"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 ff 00 00 00 5f d2 61 d2 9c}  //weight: 1, accuracy: High
        $x_1_2 = {41 33 64 71 33 64 65 65 35 34 66 2e 72 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_IW_2147711337_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IW!bit"
        threat_id = "2147711337"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {91 61 b4 9c ?? 03 6f 2a 00 00 0a 17 da 33 04 16 ?? 2b 04 ?? 17 d6 ?? 11 05 17 d6 13 05 11 05 11 06 31}  //weight: 5, accuracy: Low
        $x_1_2 = "TG9hZA==" wide //weight: 1
        $x_1_3 = "R2V0VHlwZQ==" wide //weight: 1
        $x_1_4 = "R2V0TWV0aG9k" wide //weight: 1
        $x_1_5 = "SW52b2tl" wide //weight: 1
        $x_1_6 = "RW50cnlQb2ludA==" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_IY_2147711439_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.IY!bit"
        threat_id = "2147711439"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5d 8c 27 00 00 01 13 ?? ?? 11 ?? ?? 11 ?? ?? ?? 11 ?? 28 ?? 00 00 0a 91 61 9c 11 ?? 17 58 13 ?? 11 ?? 11 ?? 31}  //weight: 1, accuracy: Low
        $x_1_2 = {50 6f 77 65 72 65 64 42 79 41 74 74 72 69 62 75 74 65 00 53 6d 61 72 74 41 73 73 65 6d 62 6c 79 2e 41 74 74 72 69 62 75 74 65 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_Z_2147712131_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.Z!bit"
        threat_id = "2147712131"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e 69 5d 58 47 61 d2 52 ?? 17 58 10 00 d3 ?? 58 ?? d3 ?? 58 47 ?? d3 ?? 7e ?? 00 00 04}  //weight: 1, accuracy: Low
        $x_1_2 = {6f 3a 00 00 0a 5d 58 47 61 d2 52 ?? 17 58 10 00 d3 ?? 58 ?? d3 ?? 58 47 ?? d3 ?? 7e ?? 00 00 04}  //weight: 1, accuracy: Low
        $x_2_3 = {53 00 54 79 70 65 00 47 54 00 4b}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_AA_2147712302_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.AA!bit"
        threat_id = "2147712302"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e b7 5d 91 61 ?? 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c}  //weight: 1, accuracy: Low
        $x_1_2 = {03 28 06 00 00 0a 16 fe 03 65 0c}  //weight: 1, accuracy: High
        $x_1_3 = "IE.IE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_JA_2147712915_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.JA"
        threat_id = "2147712915"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 08 03 07 17 28 ?? 00 00 0a 28 ?? 00 00 0a 61 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 b5 0b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_JA_2147714343_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.JA!bit"
        threat_id = "2147714343"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 24 00 00 0a 72 ?? 00 00 70 6f 25 00 00 0a 0a 06 6f 26 00 00 0a d4 8d 1a 00 00 01 0b 06 07 16 07 8e 69 6f 27 00 00 0a 26 07 0c de 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {06 d3 08 58 06 d3 08 58 47 07 d3 08 02 7b 04 00 00 04 8e 69 5d 58 47 61 d2 52 08 17 58 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_JB_2147716110_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.JB!bit"
        threat_id = "2147716110"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {2b 11 07 08 07 08 91 02 08 1f 10 5d 91 61 9c 08 17 d6 0c 08 09 31 eb 07 0a 2b 00 06 2a}  //weight: 2, accuracy: High
        $x_1_2 = {00 73 75 63 6b 69 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SI_2147716905_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SI!bit"
        threat_id = "2147716905"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00 4d 65 74 68 6f 64 42 61 73 65 00 49 6e 76 6f 6b 65}  //weight: 1, accuracy: High
        $x_1_2 = {06 1b 58 7e 18 00 00 04 8e 69 58 0b 7e 0e 00 00 04 06 91 0c 7e 18 00 00 04 06 1f 1c 5d 91 07 1f 1f 5f 63 0d 09 28 04 00 00 06 13 04 7e 0e 00 00 04 06 08 11 04 28 06 00 00 06 9c 06 17 58 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SJ_2147717385_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SJ!bit"
        threat_id = "2147717385"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 4c 00 6f 00 61 00 64 00 00 15 45 00 6e 00 74 00 72 00 79 00 70 00 6f 00 69 00 6e 00 74 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {74 00 70 00 61 00 73 00 [0-16] 68 00 69 00 74 00 74 00 [0-16] 79 00 74 00 65 00 73 00 [0-16] 6d 00 79 00 73 00 [0-16] 73 00 77 00 6f 00 72 00 64 00 [0-16] 65 00 67 00 75 00 69 00}  //weight: 1, accuracy: Low
        $x_1_3 = {52 69 6a 6e 64 61 65 6c [0-32] 52 66 63 32 38 39 38 44 65 72 69 76 65 42 79 74 65 73}  //weight: 1, accuracy: Low
        $x_1_4 = "cIfHeflW.Resources.resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SM_2147717430_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SM!bit"
        threat_id = "2147717430"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QTNbhL^[[NW]h^" wide //weight: 1
        $x_1_2 = "krnMuu7muu" wide //weight: 1
        $x_1_3 = "Vjrw" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_MSIL_Injector_SN_2147718754_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SN!bit"
        threat_id = "2147718754"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {da 02 11 04 91 06 61 ?? 11 04 ?? 8e b7 5d 91 61 9c 11 04 17 d6 13 04}  //weight: 1, accuracy: Low
        $x_1_2 = {67 65 74 5f 57 69 64 74 68 00 67 65 74 5f 48 65 69 67 68 74 00 47 65 74 50 69 78 65 6c 00 67 65 74 5f 52 00 67 65 74 5f 47 00 67 65 74 5f 42}  //weight: 1, accuracy: High
        $x_1_3 = {52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00 [0-32] 2e 00 50 00 6e 00 67 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SO_2147718755_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SO!bit"
        threat_id = "2147718755"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "TG9hZA==" wide //weight: 1
        $x_1_2 = "Q2FsbEJ5TmFtZQ==" wide //weight: 1
        $x_1_3 = "R2V0T2JqZWN0VmFsdWU=" wide //weight: 1
        $x_1_4 = "Post_MarkMail.Resources.resources" ascii //weight: 1
        $x_2_5 = {53 00 74 00 61 00 72 00 74 00 75 00 70 00 46 00 69 00 6c 00 65 00 [0-16] 52 00 75 00 6e 00 4f 00 6e 00 52 00 65 00 62 00 6f 00 6f 00 74 00}  //weight: 2, accuracy: Low
        $x_2_6 = {48 00 69 00 64 00 64 00 65 00 6e 00 41 00 74 00 72 00 69 00 62 00 [0-16] 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 24 00}  //weight: 2, accuracy: Low
        $x_2_7 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 65 00 72 00 49 00 [0-16] 41 00 6e 00 74 00 69 00 73 00 4f 00 70 00 74 00 69 00 6f 00 6e 00 73 00}  //weight: 2, accuracy: Low
        $x_2_8 = {42 00 79 00 70 00 61 00 73 00 73 00 4d 00 65 00 6d 00 6f 00 72 00 79 00 [0-16] 53 00 74 00 61 00 72 00 74 00 42 00 6f 00 74 00 4b 00 69 00 6c 00 6c 00 65 00 72 00}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_SP_2147719005_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SP!bit"
        threat_id = "2147719005"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 00 45 00 4c 00 45 00 43 00 54 00 20 00 2a 00 20 00 46 00 52 00 4f 00 4d 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 [0-16] 6d 00 61 00 6e 00 75 00 66 00 61 00 63 00 74 00 75 00 72 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_2 = {77 00 69 00 72 00 65 00 73 00 68 00 61 00 72 00 6b 00 [0-16] 46 00 69 00 64 00 64 00 6c 00 65 00 72 00 [0-16] 73 00 6d 00 73 00 6e 00 69 00 66 00 66 00 [0-16] 54 00 43 00 50 00 45 00 79 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = {63 00 63 00 73 00 76 00 68 00 73 00 74 00 [0-16] 4e 00 6f 00 72 00 74 00 6f 00 6e 00 20 00 33 00 36 00 30 00 [0-16] 65 00 67 00 75 00 69 00 [0-16] 45 00 73 00 65 00 74 00}  //weight: 1, accuracy: Low
        $x_1_4 = {74 00 61 00 73 00 6b 00 6d 00 67 00 72 00 [0-16] 63 00 6d 00 64 00 [0-16] 6d 00 73 00 63 00 6f 00 6e 00 66 00 69 00 67 00 [0-16] 72 00 65 00 67 00 65 00 64 00 69 00 74 00 [0-16] 72 00 73 00 74 00 72 00 75 00 69 00}  //weight: 1, accuracy: Low
        $x_1_5 = "cmd.exe /k ping 0 & del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SQ_2147719932_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SQ!bit"
        threat_id = "2147719932"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "huiZdkmkIwIIrB" wide //weight: 1
        $x_1_2 = {08 07 8e 69 17 59 2e 1e 7e ?? ?? ?? ?? 7e ?? ?? ?? ?? 07 08 91 1f ?? 61 d2 9c 7e ?? ?? ?? ?? 17 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SR_2147720392_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SR!bit"
        threat_id = "2147720392"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 11 04 da 03 11 04 91 ?? 61 ?? 11 04 ?? 8e b7 5d 91 61 9c 11 04 17 d6}  //weight: 1, accuracy: Low
        $x_1_2 = "INSERT INTO stock VALUES('sssa')" wide //weight: 1
        $x_1_3 = {50 00 6e 00 67 00 [0-48] 4e 00 61 00 6d 00 65 00 [0-16] 54 00 6f 00 4c 00 6f 00 77 00 65 00 72 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SV_2147732295_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SV!bit"
        threat_id = "2147732295"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "d3VhdWNsdCQ=" wide //weight: 1
        $x_1_2 = "\\wmpnetwk\\wmpnetwk" ascii //weight: 1
        $x_1_3 = "_Encrypted$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SV_2147732295_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SV!bit"
        threat_id = "2147732295"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "nSub.g.resources" ascii //weight: 1
        $x_1_2 = "FLib.FLib" wide //weight: 1
        $x_1_3 = {06 08 06 8e b7 5d 91 61 02 08 17 d6 02 8e b7 5d 91 da 20 ?? ?? ?? ?? d6 20 ?? ?? ?? ?? 5d b4}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SV_2147732295_2
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SV!bit"
        threat_id = "2147732295"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "InjectionEnum" ascii //weight: 1
        $x_1_2 = {76 00 62 00 63 00 2e 00 65 00 78 00 65 00 [0-16] 52 00 65 00 67 00 41 00 73 00 6d 00 2e 00 65 00 78 00 65 00 [0-16] 73 00 76 00 63 00 68 00 6f 00 73 00 74 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_3 = "Create /TN \"Update" wide //weight: 1
        $x_1_4 = ":ZONE.identifier & exit" wide //weight: 1
        $x_1_5 = {03 09 03 8e 69 5d 91 61 02 09 17 d6 02 8e 69 5d 91 da 20 00 01 00 00 d6 20 00 01 00 00 5d b4 9c 09 17 d6 0d}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_JM_2147732935_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.JM"
        threat_id = "2147732935"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {16 0a 1f 0b 13 05 2b b6 05 04 61 1f 3d 59 06 61}  //weight: 1, accuracy: High
        $x_1_2 = {26 1f 0a 13 0e 2b a5 03 20 c7 11 5a 0c 61 04 61 0a}  //weight: 1, accuracy: High
        $x_1_3 = "$93e86973-60b7-4837-af92-941899fb3dc0" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_TF_2147732970_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TF!bit"
        threat_id = "2147732970"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 49 6e 6a 48 6f 73 74 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 44 6f 63 74 6f 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 53 74 72 52 65 76 65 72 73 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 74 52 65 73 75 6d 65 54 68 72 65 61 64 00 4e 74 53 65 74 43 6f 6e 74 65 78 74 54 68 72 65 61 64 00 56 69 72 74 75 61 6c 41 6c 6c 6f 63 45 78 00 4e 74 57 72 69 74 65 56 69 72 74 75 61 6c 4d 65 6d 6f 72 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_TI_2147732971_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TI!bit"
        threat_id = "2147732971"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {28 1c 00 00 06 03 6f 12 00 00 0a 74 01 00 00 1b 0a 16 0b 2b 15 7e 01 00 00 04 06 07 91 1f ?? 61 d2 6f 13 00 00 0a 07 17 58 0b 07 06 8e 69 17 59 32 e3 16 2a}  //weight: 2, accuracy: Low
        $x_2_2 = {47 65 74 4f 62 6a 65 63 74 00 41 64 64 00 54 6f 41 72 72 61 79 00 41 73 73 65 6d 62 6c 79 00 4c 6f 61 64 00}  //weight: 2, accuracy: High
        $x_1_3 = "_TextChanged" ascii //weight: 1
        $x_1_4 = "_SelectedValueChanged" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_TJ_2147732974_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TJ!bit"
        threat_id = "2147732974"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e b7 17 da 11 04 da 02 11 04 91 ?? 61 28 21 00 00 0a 72 ?? 00 00 70 6f 24 00 00 0a 06 91 61 9c 11 04 17 d6 13 04}  //weight: 2, accuracy: Low
        $x_1_2 = {42 79 74 65 00 4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 00 4c 61 74 65 47 65 74}  //weight: 1, accuracy: High
        $x_1_3 = {47 65 74 42 79 74 65 73 00 67 65 74 5f 55 54 46 38 00 53 79 73 74 65 6d 2e 49 4f 2e 43 6f 6d 70 72 65 73 73 69 6f 6e 00 44 65 66 6c 61 74 65 53 74 72 65 61 6d 00 53 79 73 74 65 6d 2e 49 4f 00 4d 65 6d 6f 72 79 53 74 72 65 61 6d 00 53 74 72 65 61 6d 00 43 6f 6d 70 72 65 73 73 69 6f 6e 4d 6f 64 65 00 52 65 61 64 00 57 72 69 74 65 00 54 6f 41 72 72 61 79}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_TL_2147732983_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TL!bit"
        threat_id = "2147732983"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 61 73 73 65 6d 62 6c 79 5f 4c 6f 61 64 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 44 65 63 6f 6d 70 72 65 73 73 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 45 78 74 72 61 63 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {2e 00 62 00 69 00 6e 00 [0-32] 2e 00 52 00 65 00 73 00 6f 00 75 00 72 00 63 00 65 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_TM_2147732984_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TM!bit"
        threat_id = "2147732984"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 16 0b 2b 22 06 02 07 6f ?? 00 00 0a 03 07 03 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 61 d1 6f ?? 00 00 0a 26 07 17 58 0b 07 02 6f ?? 00 00 0a 32 d5 06 6f ?? 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {00 49 43 6c 69 65 6e 74 00 44 6f 77 6e 6c 6f 61 64 44 4c 4c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 47 65 74 44 6f 77 6e 6c 6f 61 64 44 4c 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_TO_2147732986_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TO!bit"
        threat_id = "2147732986"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {19 d8 18 d6 11 ?? 8c ?? 00 00 01 14 72 ?? 00 00 70 16 8d ?? 00 00 01 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 9c ?? ?? 19 d8 17 d6 11 ?? 8c ?? 00 00 01 14 72 ?? 00 00 70 16 8d ?? 00 00 01 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 9c ?? ?? 19 d8 11 ?? 8c ?? 00 00 01 14 72 ?? 00 00 70 16 8d ?? 00 00 01 14 14 28 ?? 00 00 0a 28 ?? 00 00 0a 9c ?? 17 d6 ?? 11 ?? 17 d6 13}  //weight: 2, accuracy: Low
        $x_2_2 = {02 03 61 8c ?? 00 00 01 2a}  //weight: 2, accuracy: Low
        $x_1_3 = {43 6f 6c 6f 72 00 49 6d 61 67 65 00 67 65 74 5f 57 69 64 74 68 00 67 65 74 5f 48 65 69 67 68 74}  //weight: 1, accuracy: High
        $x_1_4 = {47 00 65 00 74 00 50 00 69 00 78 00 65 00 6c 00 ?? ?? 52 00 ?? ?? 47 00 ?? ?? 42 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_TQ_2147732988_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TQ!bit"
        threat_id = "2147732988"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 5f b7 95 84 28 ?? 00 00 06 28 ?? 00 00 0a 9c 11 ?? 17 d6 13 05 00 20 ff 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {02 03 61 8c ?? 00 00 01 2a}  //weight: 1, accuracy: Low
        $x_1_3 = {0d 4c 00 65 00 6e 00 67 00 74 00 68 00}  //weight: 1, accuracy: High
        $x_1_4 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 00 4c 61 74 65 47 65 74 00 4c 61 74 65 49 6e 64 65 78 47 65 74 00 53 74 72 69 6e 67 00 43 6f 6e 63 61 74 00 55 49 6e 74 33 32 00 53 75 62 74 72 61 63 74 4f 62 6a 65 63 74 00 54 6f 49 6e 74 65 67 65 72 00 4d 6f 64 4f 62 6a 65 63 74 00 41 64 64 4f 62 6a 65 63 74 00 41 6e 64 4f 62 6a 65 63 74 00 54 6f 55 49 6e 74 65 67 65 72 00 54 6f 42 79 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_TS_2147732992_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TS!bit"
        threat_id = "2147732992"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 8c 1a 00 00 01 28 2a 00 00 0a 28 2b 00 00 0a 9c 11 07 17 d6 13 07}  //weight: 1, accuracy: High
        $x_1_2 = {0d 4c 00 65 00 6e 00 67 00 74 00 68 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 75 62 74 72 61 63 74 4f 62 6a 65 63 74 00 54 6f 49 6e 74 65 67 65 72 00 4d 6f 64 4f 62 6a 65 63 74 00 41 64 64 4f 62 6a 65 63 74 00 41 6e 64 4f 62 6a 65 63 74 00 54 6f 55 49 6e 74 65 67 65 72 00 58 6f 72 4f 62 6a 65 63 74 00 54 6f 42 79 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_TT_2147732993_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TT!bit"
        threat_id = "2147732993"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8e b7 17 da ?? da 03 ?? 91 ?? 61 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a ?? 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 8e b7 5d 91 61 9c ?? 17 d6 0d}  //weight: 1, accuracy: Low
        $x_1_2 = {00 72 70 2e 64 6c 6c 00 00 00 00 0f 61 00 70 00 70 00 64 00 61 00 74 00 61 00}  //weight: 1, accuracy: High
        $x_1_3 = {43 6f 6c 6f 72 00 49 6d 61 67 65 00 67 65 74 5f 57 69 64 74 68 00 67 65 74 5f 48 65 69 67 68 74}  //weight: 1, accuracy: High
        $x_1_4 = {47 00 65 00 74 00 50 00 69 00 78 00 65 00 6c 00 ?? ?? 52 00 ?? ?? 47 00 ?? ?? 42 00}  //weight: 1, accuracy: Low
        $x_1_5 = {00 47 65 74 50 72 6f 63 65 73 73 42 79 49 64 00 4b 69 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_TY_2147733007_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TY!bit"
        threat_id = "2147733007"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8e b7 17 da 09 da 02 09 91 ?? 61 28 1e 00 00 0a 72 01 00 00 70 6f 1f 00 00 0a 09 28 1e 00 00 0a 72 01 00 00 70 6f 1f 00 00 0a 8e b7 5d 91 61 9c 09 17 d6 0d}  //weight: 2, accuracy: Low
        $x_1_2 = {4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67 00 4c 61 74 65 47 65 74 00 49 6e 74 33 32 00 4c 61 74 65 49 6e 64 65 78 47 65 74}  //weight: 1, accuracy: High
        $x_1_3 = {45 6e 63 6f 64 69 6e 67 00 67 65 74 5f 44 65 66 61 75 6c 74 00 47 65 74 42 79 74 65 73}  //weight: 1, accuracy: High
        $x_1_4 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 00 52 75 6e 74 69 6d 65 48 65 6c 70 65 72 73 00 47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_UA_2147733009_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.UA!bit"
        threat_id = "2147733009"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0c 08 03 61 0c 06 08 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 07 17 58 0b 07 02 6f ?? 00 00 0a 32 d5 06 2a}  //weight: 10, accuracy: Low
        $x_5_2 = {52 65 70 6c 61 63 65 00 43 6f 6d 70 69 6c 65 41 73 73 65 6d 62 6c 79 46 72 6f 6d 53 6f 75 72 63 65 00 67 65 74 5f 43 6f 6d 70 69 6c 65 64 41 73 73 65 6d 62 6c 79 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00 49 6e 76 6f 6b 65}  //weight: 5, accuracy: High
        $x_1_3 = "System.Drawing.dll" wide //weight: 1
        $x_1_4 = "U3lzdGVtLkRyYXdpbmcuZGxs" wide //weight: 1
        $x_1_5 = "/optimize+ /platform:X86 /debug+ /target:winexe" wide //weight: 1
        $x_1_6 = "L29wdGltaXplKyAvcGxhdGZvcm06WDg2IC9kZWJ1ZysgL3RhcmdldDp3aW5leGU=" wide //weight: 1
        $x_1_7 = {23 00 72 00 65 00 73 00 6e 00 61 00 6d 00 65 00 23 00 [0-48] 23 00 70 00 61 00 73 00 73 00 23 00}  //weight: 1, accuracy: Low
        $x_1_8 = {49 00 33 00 4a 00 6c 00 63 00 32 00 35 00 68 00 62 00 57 00 55 00 6a 00 [0-48] 49 00 33 00 42 00 68 00 63 00 33 00 4d 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_UD_2147733010_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.UD!bit"
        threat_id = "2147733010"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {23 00 72 00 65 00 73 00 6e 00 61 00 6d 00 65 00 23 00 [0-48] 23 00 70 00 61 00 73 00 73 00 23 00}  //weight: 1, accuracy: Low
        $x_1_2 = "System.Drawing.dll" wide //weight: 1
        $x_1_3 = "System.Management.dll" wide //weight: 1
        $x_1_4 = "/optimize+ /platform:X86 /debug+ /target:winexe" wide //weight: 1
        $x_1_5 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 52 65 70 6c 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 43 6f 6d 70 69 6c 65 41 73 73 65 6d 62 6c 79 46 72 6f 6d 53 6f 75 72 63 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_UE_2147733016_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.UE!bit"
        threat_id = "2147733016"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "#emanser#" wide //weight: 1
        $x_1_2 = "#ssap#" wide //weight: 1
        $x_1_3 = "lld.eroC.metsyS" wide //weight: 1
        $x_1_4 = "lld.tnemeganaM.metsyS" wide //weight: 1
        $x_1_5 = "exeniw:tegrat/ +gubed/ 68X:mroftalp/ +ezimitpo/" wide //weight: 1
        $x_1_6 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 52 65 70 6c 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 43 6f 6d 70 69 6c 65 41 73 73 65 6d 62 6c 79 46 72 6f 6d 53 6f 75 72 63 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_UF_2147733017_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.UF!bit"
        threat_id = "2147733017"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 00 45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 41 74 74 72 69 62 75 74 65 00 45 64 69 74 6f 72 42 72 6f 77 73 61 62 6c 65 53 74 61 74 65 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 2, accuracy: Low
        $x_1_2 = {53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 62 75 73 6e 65 74 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_UG_2147733018_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.UG!bit"
        threat_id = "2147733018"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 72 65 73 6f 75 72 63 65 73 00 ?? ?? ?? ?? ?? ?? ?? ?? 2d ?? ?? ?? ?? 2d ?? ?? 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73}  //weight: 1, accuracy: Low
        $x_1_2 = {15 53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00}  //weight: 1, accuracy: Low
        $x_1_3 = {00 3c 4d 6f 64 75 6c 65 3e 00}  //weight: 1, accuracy: High
        $x_1_4 = "System.CodeDom.Compiler" ascii //weight: 1
        $x_1_5 = "GeneratedCodeAttribute" ascii //weight: 1
        $x_1_6 = "get_EntryPoint" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_UI_2147733019_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.UI!bit"
        threat_id = "2147733019"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "153"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 00 08 00 2d ?? ?? ?? ?? 2d}  //weight: 100, accuracy: Low
        $x_10_2 = {00 3c 4d 6f 64 75 6c 65 3e 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 43 6f 6d 70 69 6c 65 72 47 65 6e 65 72 61 74 65 64 41 74 74 72 69 62 75 74 65 00}  //weight: 10, accuracy: High
        $x_10_4 = {00 53 79 73 74 65 6d 2e 43 6f 64 65 44 6f 6d 2e 43 6f 6d 70 69 6c 65 72 00}  //weight: 10, accuracy: High
        $x_10_5 = {89 50 4e 47 0d 0a 1a 0a 00 00 00 0d 49 48 44 52 00}  //weight: 10, accuracy: High
        $x_10_6 = {15 53 79 73 74 65 6d 2e 44 72 61 77 69 6e 67 2e 42 69 74 6d 61 70}  //weight: 10, accuracy: High
        $x_1_7 = {00 67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 49 6e 76 6f 6b 65 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 41 73 73 65 6d 62 6c 79 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 41 70 70 44 6f 6d 61 69 6e 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 47 65 74 44 6f 6d 61 69 6e 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 5 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_TR_2147733022_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TR!bit"
        threat_id = "2147733022"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {52 65 67 65 78 00 52 65 70 6c 61 63 65 00 67 65 74 5f 4c 65 6e 67 74 68 00 4d 61 74 68}  //weight: 1, accuracy: High
        $x_1_2 = {53 00 74 00 61 00 72 00 74 00 75 00 70 00 [0-2] 43 00 72 00 65 00 61 00 74 00 65 00 53 00 68 00 6f 00 72 00 74 00 63 00 75 00 74 00}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 00 6f 00 61 00 64 00 [0-2] 45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 [0-2] 49 00 6e 00 76 00 6f 00 6b 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = "https://pastebin.com/raw" wide //weight: 1
        $x_1_5 = {53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 [0-2] 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 55 00 70 00 64 00 61 00 74 00 65 00 72 00}  //weight: 1, accuracy: Low
        $x_1_6 = "schtasks /Create /SC minute /MO" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_DT_2147733078_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.DT!bit"
        threat_id = "2147733078"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SandboxArtifactsPresent" ascii //weight: 1
        $x_1_2 = "CreateStartupShortcut" ascii //weight: 1
        $x_1_3 = "RunInMemory" ascii //weight: 1
        $x_1_4 = "SpawnNewProcess" ascii //weight: 1
        $x_1_5 = "ReclaimMutex" ascii //weight: 1
        $x_1_6 = "MonitorSpawnling" ascii //weight: 1
        $x_1_7 = "antiVMS" ascii //weight: 1
        $x_1_8 = "MonitorPackageHost" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_MSIL_Injector_DP_2147733079_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.DP!bit"
        threat_id = "2147733079"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {43 68 61 70 74 65 72 4f 6e 65 00 49 6e 74 72 6f}  //weight: 1, accuracy: High
        $x_1_2 = "r3tri3v3RunP3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_DO_2147733080_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.DO!bit"
        threat_id = "2147733080"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8c 16 00 00 01 a2 [0-4] 14 28 20 00 00 0a [0-4] b4 8c 14 00 00 01 28 23 00 00 0a 28 24 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {28 1f 00 00 0a [0-4] 1b d6 [0-4] 20 ff 00 00 00 5f d8}  //weight: 1, accuracy: Low
        $x_1_3 = {4c 61 74 65 49 6e 64 65 78 47 65 74 00 41 64 64 4f 62 6a 65 63 74 00 4d 6f 64 4f 62 6a 65 63 74 00 58 6f 72 4f 62 6a 65 63 74 00 54 6f 42 79 74 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_TZ_2147733087_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.TZ!bit"
        threat_id = "2147733087"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b7 17 da 09 da 03 09 91 08 61 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 09 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a 8e b7 5d 91 61 9c 09 17 d6 0d 09 11 04}  //weight: 1, accuracy: Low
        $x_1_2 = {00 72 70 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 42 6c 6f 63 6b 43 6f 70 79 00 47 65 74 50 72 6f 63 65 73 73 42 79 49 64 00 4b 69 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_SA_2147733088_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.SA!bit"
        threat_id = "2147733088"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 09 da 02 09 91 8c ?? 00 00 01 ?? 8c ?? 00 00 01 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 72 ?? 00 00 70 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {58 6f 72 4f 62 6a 65 63 74 00 47 65 74 53 74 72 69 6e 67 00 4e 65 77 4c 61 74 65 42 69 6e 64 69 6e 67}  //weight: 1, accuracy: High
        $x_1_3 = {53 79 73 74 65 6d 2e 52 75 6e 74 69 6d 65 2e 43 6f 6d 70 69 6c 65 72 53 65 72 76 69 63 65 73 00 52 75 6e 74 69 6d 65 48 65 6c 70 65 72 73 00 47 65 74 4f 62 6a 65 63 74 56 61 6c 75 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_VA_2147733107_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VA!bit"
        threat_id = "2147733107"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunPE.Protect" wide //weight: 1
        $x_1_2 = {6f 08 00 00 0a 0d 06 09 6c 23 00 00 00 00 00 00 18 40 5b 23 00 00 00 00 00 00 18 40 5b 23 00 00 00 00 00 00 1c 40 5b 28 09 00 00 0a b7 28 0a 00 00 0a 28 0b 00 00 0a}  //weight: 1, accuracy: High
        $x_1_3 = {44 65 63 72 79 70 74 00 4c 6f 61 64 69 6e 67 00 4d 61 69 6e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_VB_2147733110_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VB!bit"
        threat_id = "2147733110"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "102"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {06 07 1f 10 5d 91 61 d2 81 ?? 00 00 01 07 17 58 0b 0d 00 02 07 8f ?? 00 00 01 25 71 ?? 00 00 01}  //weight: 100, accuracy: Low
        $x_1_2 = {03 20 20 a7 00 00 59 02 7b ?? 00 00 04 61 d1}  //weight: 1, accuracy: Low
        $x_1_3 = {53 65 6c 65 63 74 00 54 6f 41 72 72 61 79 00 43 6f 6e 76 65 72 74 00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67}  //weight: 1, accuracy: High
        $x_1_4 = {4c 6f 61 64 52 65 73 6f 75 72 63 65 00 4c 6f 63 6b 52 65 73 6f 75 72 63 65 00 68 52 65 73 44 61 74 61}  //weight: 1, accuracy: High
        $x_1_5 = {45 6e 63 6f 64 69 6e 67 00 53 79 73 74 65 6d 2e 54 65 78 74 00 67 65 74 5f 55 6e 69 63 6f 64 65 00 47 65 74 42 79 74 65 73}  //weight: 1, accuracy: High
        $x_1_6 = {02 11 04 11 05 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 28 ?? 00 00 0a 16 08 09 1a 28 ?? 00 00 0a 09 1a 58 0d 11 05 17 58 13}  //weight: 1, accuracy: Low
        $x_1_7 = {49 6d 61 67 65 00 67 65 74 5f 57 69 64 74 68 00 43 6f 6c 6f 72 00 47 65 74 50 69 78 65 6c 00 54 6f 41 72 67 62}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_VD_2147733112_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VD!bit"
        threat_id = "2147733112"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 25 4b 04 06 1f 0f 5f 95 61 54 04 06 1f 0f 5f 04 06 1f 0f 5f 95 03 25 1a 58 10 01 4b 61 20 84 e2 03 78 58 9e 06 17 58 0a 07 17 58 0b 07 02 37 cf}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_VE_2147733113_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VE!bit"
        threat_id = "2147733113"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 0b 02 07 8f ?? 00 00 01 25 47 03 06 ?? 6f 04 00 00 0a 5d 91 06 1b 58 03 8e 69 58 1f 1f 5f 63 20 ?? 00 00 00 5f d2 61 d2 52 06 17 58 0a 06 02 8e 69}  //weight: 1, accuracy: Low
        $x_1_2 = {67 65 74 5f 4c 65 6e 67 74 68 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00 49 6e 76 6f 6b 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_VF_2147733114_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VF!bit"
        threat_id = "2147733114"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 04 1f 1f 63 08 61 11 04 1f 1f 63 09 61 31 9e ?? ?? 2b 00}  //weight: 10, accuracy: Low
        $x_10_2 = {11 0f 1f 1f 63 11 0d 61 11 0f 1f 1f 63 11 0e 61}  //weight: 10, accuracy: High
        $x_1_3 = {02 1f 3c d6 28 ?? 00 00 0a 28 ?? 00 00 0a [0-32] d6 1f 78 d6}  //weight: 1, accuracy: Low
        $x_1_4 = {13 05 11 05 7e ?? 00 00 04 19 94 33 18 ?? ?? 0f 00 28 ?? 00 00 0a 08 d6 28 ?? 00 00 0a 28 ?? 00 00 0a 9c 2b 23 11 05 7e ?? 00 00 04 1f 0f 94 33 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_VH_2147733121_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VH!bit"
        threat_id = "2147733121"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FZQR27Y43sDbON97KOJGAg==.bat" wide //weight: 1
        $x_1_2 = "GSDGSDGSDGSD" wide //weight: 1
        $x_1_3 = "#nsdffdsp#$$$.exe$$$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule VirTool_MSIL_Injector_VI_2147733122_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VI!bit"
        threat_id = "2147733122"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5a 20 e8 03 00 00 6a 5b 0b 06 07 00 0a 02 7e ?? 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {11 05 11 0a ?? ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b ?? ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1}  //weight: 1, accuracy: Low
        $x_1_3 = "bibdag.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_VJ_2147733125_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VJ!bit"
        threat_id = "2147733125"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 11 0a ?? ?? 00 00 1b 11 0c 11 07 58 11 09 59 93 61 11 0b ?? ?? 00 00 1b 11 09 11 0c 58 1f 11 58 11 08 5d 93 61 d1}  //weight: 1, accuracy: Low
        $x_1_2 = {03 04 61 1f ?? 59 06 61 45 01 00 00 00 10 00 00 00 09 20 ?? ?? ?? ?? 94 20 ?? ?? ?? ?? 59 0c 2b ab 1e 2b fa}  //weight: 1, accuracy: Low
        $x_1_3 = {00 46 6f 72 4d 65 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_VK_2147733126_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VK!bit"
        threat_id = "2147733126"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 05 25 4b 11 0c 11 0f 1f 0f 5f 95 61 54 11 0c 11 0f 1f 0f 5f 11 0c 11 0f 1f 0f 5f 95 11 05 25 1a 58 13 05 4b 61 20 19 28 bb 3d 58 9e 11 0f 17 58 13 0f 11 16 17 58 13 16 11 16 11 06 37 c1}  //weight: 1, accuracy: High
        $x_1_2 = {1f 40 13 0e 7e ?? 00 00 04 11 05 28 ?? 00 00 0a 11 06 18 62 11 0e 12 0e 6f ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_VL_2147733127_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VL!bit"
        threat_id = "2147733127"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RunPEDLL.dll" wide //weight: 1
        $x_1_2 = "REGGIE" wide //weight: 1
        $x_1_3 = "FAULTY" wide //weight: 1
        $x_1_4 = "SVCHEHE" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_MD_2147733149_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.MD!bit"
        threat_id = "2147733149"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {02 06 02 06 91 03 07 91 61 d2 9c 07 17 58 0b 07 03 8e 69 32 eb 06 17 58 0a}  //weight: 1, accuracy: High
        $x_1_2 = {45 00 6e 00 74 00 72 00 79 00 50 00 6f 00 69 00 6e 00 74 00 ?? ?? 47 00 65 00 74 00 45 00 78 00 65 00 63 00 75 00 74 00 69 00 6e 00 67 00 41 00 73 00 73 00 65 00 6d 00 62 00 6c 00 79 00 ?? ?? 4c 00 6f 00 61 00 64 00}  //weight: 1, accuracy: Low
        $x_1_3 = {53 79 73 74 65 6d 2e 52 65 66 6c 65 63 74 69 6f 6e 00 4d 65 74 68 6f 64 49 6e 66 6f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_VO_2147733152_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.VO!MTB"
        threat_id = "2147733152"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 09 17 72 ?? ?? 00 70 a2 11 09 18 28 33 00 00 0a a2 11 09 14 14 14 28 20 00 00 0a 28 11 00 00 0a 14 28 21 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {28 2f 00 00 0a}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_DS_2147733638_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.DS!bit"
        threat_id = "2147733638"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 02 06 02 8e 69 5d 02 06 02 8e 69 5d 91 03 06 03 8e 69 5d 91 61 02 06 17 58 02 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 20 03 00 00 00 16}  //weight: 1, accuracy: High
        $x_1_2 = {00 06 08 06 8e 69 5d 06 08 06 8e 69 5d 91 07 08 07 8e 69 5d 91 61 06 08 17 58 06 8e 69 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 08 17 59 0c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule VirTool_MSIL_Injector_DU_2147733675_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.DU!bit"
        threat_id = "2147733675"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 91 02 03 02 8e 69 5d 91 61 d2 9c 2a 0b 00 7e ?? 00 00 04 03 7e ?? 00 00 04 03}  //weight: 1, accuracy: Low
        $x_1_2 = {20 e8 03 00 00 5a 0a 16 0c 00 73 ?? 00 00 0a 19 1d 6f ?? 00 00 0a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_DV_2147733711_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.DV!bit"
        threat_id = "2147733711"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {02 20 20 a7 00 00 59 7e ?? 00 00 04 16 6f ?? 00 00 0a 20 20 a7 00 00 59 61 d1 2a}  //weight: 10, accuracy: Low
        $x_1_2 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 4c 6f 61 64 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00 49 6e 76 6f 6b 65 00 53 75 62 73 74 72 69 6e 67}  //weight: 1, accuracy: High
        $x_1_3 = {42 61 73 65 36 34 53 74 72 69 6e 67 00 42 79 74 65 00 41 73 73 65 6d 62 6c 79 00 4c 6f 61 64 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_MSIL_Injector_YG_2147739879_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.YG!bit"
        threat_id = "2147739879"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {06 02 07 6f 20 00 00 0a 03 07 03 6f 17 00 00 0a 5d 6f 20 00 00 0a 61 d1 6f 21 00 00 0a 26 07 17 58 0b}  //weight: 1, accuracy: High
        $x_1_2 = {00 46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 00 68 65 78 53 74 72 69 6e 67 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 62 61 73 65 36 34 00 6b 65 79 00 72 65 70 6c 61 63 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 4c 6f 61 64 00 4d 65 74 68 6f 64 49 6e 66 6f 00 67 65 74 5f 45 6e 74 72 79 50 6f 69 6e 74 00 4d 65 74 68 6f 64 42 61 73 65 00 49 6e 76 6f 6b 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_MSIL_Injector_AA_2147745501_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:MSIL/Injector.AA!MTB"
        threat_id = "2147745501"
        type = "VirTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Injector"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CL.RunPE" wide //weight: 1
        $x_1_2 = "\\aspnet_regbrowsers.exe" wide //weight: 1
        $x_1_3 = {57 65 62 43 6c 69 65 6e 74 00 44 6f 77 6e 6c 6f 61 64 44 61 74 61}  //weight: 1, accuracy: High
        $x_1_4 = "https://1.top4top.net/" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

