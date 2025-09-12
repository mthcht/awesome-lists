rule Backdoor_MSIL_Bladabindi_B_2147659457_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 57 4c 00 44 4c 56 00 6e 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 47 65 74 4b 65 79 00 6b 65 79 00 70 72 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 66 78 00 62 00 73 70 6c 00 5a 49 50 00 43 4d 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 42 00 53 00 42 53 00 42 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 57 52 4b 00 55 53 42 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_B_2147659457_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 44 4c 56 00 6e 00 47 54 56 00 53 54 56 00 74 00 69 6e 66 00 46 52 00 45 4e 42 00 73 00 44 45 42 00 52 4e 00 63 00 53 42 00 53 00 42 53 00 42 00 66 78 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 70 72 00 53 65 6e 64 00 52 43 00 55 4e 53 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 5a 49 50 00 43 4d 00 43 61 6d 00 41 43 54 00 48 57 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_B_2147659457_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 6d 61 69 6e 00 57 4c 00 6b 6c 00 50 6c 75 67 69 6e 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 41 00 77 00 6b 6c 00 55 53 42 00}  //weight: 10, accuracy: High
        $x_1_3 = {00 49 6e 64 00 62 00 53 65 6e 64 00 53 00 52 43 00 55 4e 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 44 4c 56 00 6e 00 47 54 56 00 53 54 56 00 74 00 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 42 53 00 42 00 66 78 00 73 70 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 66 78 00 62 00 73 70 6c 00 5a 49 50 00 43 4d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_B_2147659457_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "110"
        strings_accuracy = "High"
    strings:
        $x_100_1 = {00 53 42 00 42 53 00 66 78 00}  //weight: 100, accuracy: High
        $x_1_2 = {00 44 4c 56 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 47 54 56 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 53 54 56 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 75 73 62 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 41 43 54 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 49 6e 64 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 43 61 6d 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 49 6e 73 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 55 4e 53 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 53 50 4c 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 48 57 44 00}  //weight: 1, accuracy: High
        $x_1_14 = {00 57 52 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_B_2147659457_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {61 d2 13 04 09 1e 63 08 61 d2 13 05 07 08 11 05 1e 62 11 04 60 d1 9d 08 17 58 0c 08 07 8e 69 38}  //weight: 2, accuracy: High
        $x_1_2 = {63 01 6b 02 60 03 6c 04 64 05 5c 06 01}  //weight: 1, accuracy: High
        $x_1_3 = {67 01 61 02 72 03 72 04 65 05 71 06 67 07 5d 08}  //weight: 1, accuracy: High
        $x_1_4 = {61 01 64 02 74 03 6a 04 77 05 6c 06 64 07 75 08}  //weight: 1, accuracy: High
        $x_1_5 = {42 05 43 06 40 07 5c 08 52 09 4d 0a 59 0b 49 0c}  //weight: 1, accuracy: High
        $x_1_6 = {46 06 76 07 6c 08 78 09 6b 0a 7a 0b 76 0c 75 0d}  //weight: 1, accuracy: High
        $x_1_7 = {3e 08 7b 09 2f 0a 7e 0b 64 0c 62 0d 6c 0e 2a 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_B_2147659457_5
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 3c 4d 6f 64 75 6c 65 3e 00 42 61 62 65 6c 41 74 74 72 69 62 75 74 65 00 41 00 77 00 6b 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 41 43 54 00 48 57 44 00 6d 61 69 6e 00 50 6c 75 67 69 6e 00 42 79 74 65 4f 66 50 6c 75 67 69 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 49 6e 64 00 47 65 74 4b 65 79 00 6b 65 79 00 70 72 00 53 65 6e 64 00 52 43 00 55 4e 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 57 52 4b 00 4f 66 66 00 45 78 65 4e 61 6d 65 00 64 72 00 53 74 61 72 74 00 63 6c 65 61 6e 00 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 66 78 00 62 00 73 70 6c 00 5a 49 50 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_B_2147659457_6
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 41 00 6b 6c 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 1, accuracy: High
        $x_1_2 = {00 77 2e 65 78 65 00 3c 4d 6f 64 75 6c 65 3e 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 6b 6c 00 52 65 73 6f 75 72 63 65 73 00 77 2e 4d 79 2e 52 65 73 6f 75 72 63 65 73 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 47 65 74 4b 65 79 00 52 65 67 69 73 74 72 79 4b 65 79 00 6b 65 79 00 52 65 70 6c 61 63 65 00 70 72 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 47 65 74 4b 65 79 00 6b 65 79 00 70 72 00 53 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 70 72 00 67 65 74 5f 48 61 6e 64 6c 65 00 53 65 6e 64 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 4c 6f 67 73 00 4c 6f 67 73 50 61 74 68 00 57 52 4b 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 00 57 52 4b 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 44 4c 56 00 6e 00 47 54 56 00 53 54 56 00 74 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 47 54 56 00 47 65 74 56 61 6c 75 65 00 53 54 56 00 74 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 42 53 00 42 00 66 78 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_B_2147659457_7
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 41 00 6b 6c 00 3c 4d 6f 64 75 6c 65 3e}  //weight: 10, accuracy: High
        $x_10_2 = {00 41 00 6b 6c 00 55 53 42 00 44 52 56 00}  //weight: 10, accuracy: High
        $x_10_3 = {00 3c 4d 6f 64 75 6c 65 3e 00 42 61 62 65 6c 41 74 74 72 69 62 75 74 65 00 41 00}  //weight: 10, accuracy: High
        $x_1_4 = {00 44 4c 56 00 6e 00 47 54 56 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 47 54 56 00 53 54 56 00 74 00 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 44 4c 56 00 47 54 56 00 53 54 56 00 69 6e 66 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 42 53 00 42 00 66 78 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 42 53 00 42 00 67 65 74 5f 44 65 66 61 75 6c 74 00 66 78 00}  //weight: 1, accuracy: High
        $x_1_9 = {00 53 42 00 42 53 00 66 78 00 41 72 72 61 79 00}  //weight: 1, accuracy: High
        $x_1_10 = {00 70 72 00 53 65 6e 64 00 53 6f 63 6b 65 74 46 6c 61 67 73 00}  //weight: 1, accuracy: High
        $x_1_11 = {00 49 6e 64 00 47 65 74 4b 65 79 00 6b 65 79 00 70 72 00}  //weight: 1, accuracy: High
        $x_1_12 = {00 70 72 00 53 65 6e 64 00 52 43 00}  //weight: 1, accuracy: High
        $x_1_13 = {00 70 72 00 67 65 74 5f 48 61 6e 64 6c 65 00 53 65 6e 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_B_2147659457_8
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "33"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_2 = "[endof]" wide //weight: 10
        $x_10_3 = "|'|'|" wide //weight: 10
        $x_1_4 = ".exe /k ping 0 & del \"" wide //weight: 1
        $x_1_5 = "netsh firewall add allowedprogram " wide //weight: 1
        $x_1_6 = "0.4.1a" wide //weight: 1
        $x_1_7 = "1177" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_B_2147659457_9
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B"
        threat_id = "2147659457"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "VKCodeToUnicode" ascii //weight: 2
        $x_2_2 = "get_ShiftKeyDown" ascii //weight: 2
        $x_3_3 = "[ENTER]" wide //weight: 3
        $x_3_4 = "[endof]" wide //weight: 3
        $x_3_5 = "cmd.exe /k ping 0 & del" wide //weight: 3
        $x_4_6 = "netsh firewall add allowedprogram" wide //weight: 4
        $x_2_7 = {07 57 00 69 00 6e 00 00 03 ae 00 ?? 03 22 21}  //weight: 2, accuracy: Low
        $x_3_8 = "SGFjS2Vk" wide //weight: 3
        $x_2_9 = "\" \"wscript.exe\" ENABLE" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 4 of ($x_2_*))) or
            ((4 of ($x_3_*) and 3 of ($x_2_*))) or
            ((1 of ($x_4_*) and 2 of ($x_3_*) and 4 of ($x_2_*))) or
            ((1 of ($x_4_*) and 3 of ($x_3_*) and 2 of ($x_2_*))) or
            ((1 of ($x_4_*) and 4 of ($x_3_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_C_2147660188_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.C"
        threat_id = "2147660188"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {49 6e 64 00 62 00 53 00 52 43 00 55 4e 53 00 43 6f 6d 70 44 69 72 00 46 31 00 46 32 00 49 4e 53}  //weight: 5, accuracy: High
        $x_5_2 = {45 4e 42 00 73 00 44 45 42 00 72 6e 00 4e 75 6d 62 65 72 4f 66 43 68 61 72 73 00 53 42 00 42 53}  //weight: 5, accuracy: High
        $x_1_3 = {50 00 6f 00 6c 00 69 00 63 00 69 00 65 00 73 00 5c 00 53 00 79 00 73 00 74 00 65 00 6d 00 00 13 45 00 6e 00 61 00 62 00 6c 00 65 00 4c 00 55 00 41 00}  //weight: 1, accuracy: High
        $x_1_4 = "\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "[endof]" wide //weight: 1
        $x_1_6 = "cmd.exe /k ping 0 & del" wide //weight: 1
        $x_1_7 = "netsh firewall add allowedprogram" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_F_2147666534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.F"
        threat_id = "2147666534"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "VKCodeToUnicode" ascii //weight: 1
        $x_1_2 = "netsh firewall add allowedprogram \"" wide //weight: 1
        $x_1_3 = "cmd.exe /k ping 0 & del \"" wide //weight: 1
        $x_1_4 = {07 57 00 69 00 6e 00 00 03 ae 00 ?? 03 22 21}  //weight: 1, accuracy: Low
        $x_1_5 = {16 1f 68 9d 11 20 17 1f 74 9d 11 20 18 1f 74 9d 11 20 19 1f 70 9d 11 20 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_G_2147670314_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.G"
        threat_id = "2147670314"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "39"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Classes\\" wide //weight: 1
        $x_2_2 = "/c start " wide //weight: 2
        $x_2_3 = "\\DefaultIcon\\" wide //weight: 2
        $x_4_4 = "&explorer /root,\"%CD%" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_N_2147679246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.N"
        threat_id = "2147679246"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {5e 10 69 4c e4 41 60 d5 72 71 67 a2 d1 e4 03 3c 47 d4 04 4b fd 85 0d d2 6b b5 0a a5 fa a8 b5 35 6c 98 b2 42 d6 c9 bb db 40 f9 bc ac e3 6c d8 32}  //weight: 2, accuracy: High
        $x_2_2 = {20 ac de 6c 27 20 85 46 b6 14 20 06 b0 ec 35 28}  //weight: 2, accuracy: High
        $x_2_3 = {da d3 59 d3 59 d6 b3 69 ?? 38 [0-5] 38 [0-4] 02 7b [0-4] 03 6f}  //weight: 2, accuracy: Low
        $x_2_4 = "ddb5ffd76e10450e923569ab00e2c219" ascii //weight: 2
        $x_1_5 = "server.exe" ascii //weight: 1
        $x_1_6 = "password" ascii //weight: 1
        $x_1_7 = "\\Nouveau" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_S_2147680402_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.gen!S"
        threat_id = "2147680402"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 6e 9d 06 1f ?? 1f 74 9d 06 1f ?? 1f 56 9d 06 1f ?? 1f 65 9d 06 1f ?? 1f 72 9d 06 1f ?? 1f 73 9d 06 1f ?? 1f 69 9d 06 1f ?? 1f 6f 9d 06 1f ?? 1f 6e 9d 06 1f ?? 1f 5c 9d 06 1f ?? 1f 52 9d 06 1f ?? 1f 75 9d 06 1f ?? 1f 6e}  //weight: 1, accuracy: Low
        $x_10_2 = {13 15 11 15 16 1f 2e 9d 11 15 17 1f 2e 9d 11 15 28 67 00 00 06 16 28 e4 00 00 06 16 33 0a 20 88 13 00 00 28 02 01 00 06}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_T_2147680424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.gen!T"
        threat_id = "2147680424"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {03 02 61 1f 17 59 45 01 00 00 00 04 00 00 00 16}  //weight: 1, accuracy: High
        $x_1_2 = {04 03 61 1f 43 59 45 01 00 00 00 04 00 00 00 1c}  //weight: 1, accuracy: High
        $x_10_3 = {20 7b 30 00 00 9d 06 1a 20 34 1d 00 00 9d 06 1b 20 97 1f 00 00 9d}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_T_2147680424_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.gen!T"
        threat_id = "2147680424"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {d0 1b 00 00 06 26 1b 0a 2b d0 04 03 61 1f 4b 59 45 01 00 00 00 04 00 00 00 17}  //weight: 1, accuracy: High
        $x_1_2 = {05 04 61 1f 38 59 45 01 00 00 00 04 00 00 00 16 0a 2b bd}  //weight: 1, accuracy: High
        $x_1_3 = {05 04 61 1f 39 59 45 01 00 00 00 02 00 00 00 2b ef 00 02 03}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_X_2147682078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.X"
        threat_id = "2147682078"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5b 9d 06 17 1f 65 9d 06 18 1f 6e 9d 06 19 1f 64 9d 06 1a 1f 6f 9d 06 1b 1f 66 9d 06 1c 1f 5d}  //weight: 1, accuracy: High
        $x_1_2 = {7c 9d 06 17 1f 27 9d 06 18 1f 7c 9d 06 19 1f 27 9d 06 1a 1f 7c}  //weight: 1, accuracy: High
        $x_1_3 = {00 64 72 69 76 65 00 46 69 6c 65 73 00 6c 6e 6b 00}  //weight: 1, accuracy: High
        $x_1_4 = "55-32-68-70-5A-6E-52-4C-5A-58-6C-45-62-33-64-75" wide //weight: 1
        $x_1_5 = "62-6D-56-30-63-32-67-67-5A-6D-6C-79-5A-58-64-68-62-47-77-67-59-57-52-6B-49-47-46-73-62-47-39-33-5A-57-52-77-63-6D-39-6E-63-6D" wide //weight: 1
        $x_1_6 = "59-32-31-6B-4C-6D-56-34-5A-53-41-76-61-79-42-77-61-57-35-6E-49-44-41-67-4A-69-42-6B-5A-57-77-67-49-67-3D-3D" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_Y_2147682085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.Y"
        threat_id = "2147682085"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 7c 9d 06 ?? ?? ?? ?? 1b 17 1f 27 9d 06 ?? ?? ?? ?? 1b 18 1f 7c 9d 06 ?? ?? ?? ?? 1b 19 1f 27 9d 06 ?? ?? ?? ?? 1b 1a 1f 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {1f 5b 9d 06 ?? ?? ?? ?? 1b 17 1f 65 9d 06 ?? ?? ?? ?? 1b 18 1f 6e 9d 06 ?? ?? ?? ?? 1b 19 1f 64 9d 06 ?? ?? ?? ?? 1b 1a 1f 6f 9d 06 ?? ?? ?? ?? 1b 1b 1f 66 9d 06 ?? ?? ?? ?? 1b 1c 1f 5d}  //weight: 10, accuracy: Low
        $x_1_3 = {00 41 00 77 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 57 4c 00 44 4c 56 00 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 44 4c 56 00 6e 00 47 54 56 00 53 54 56 00 74 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 6b 6c 00 4b 65 79 73 00 4c 6f 67 73 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 65 74 4b 65 79 00 6b 65 79 00 70 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AA_2147682146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AA"
        threat_id = "2147682146"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 1f 7c 9d ?? ?? ?? ?? ?? 1b 17 1f 27 9d ?? ?? ?? ?? ?? 1b 18 1f 7c 9d ?? ?? ?? ?? ?? 1b 19 1f 27 9d ?? ?? ?? ?? ?? 1b 1a 1f 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {16 1f 5b 9d ?? ?? ?? ?? ?? 1b 17 1f 65 9d ?? ?? ?? ?? ?? 1b 18 1f 6e 9d ?? ?? ?? ?? ?? 1b 19 1f 64 9d ?? ?? ?? ?? ?? 1b 1a 1f 6f 9d ?? ?? ?? ?? ?? 1b 1b 1f 66 9d ?? ?? ?? ?? ?? 1b 1c 1f 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {1f 29 1f 5c 9d ?? ?? ?? ?? ?? 1b 1f 2a 1f 52 9d ?? ?? ?? ?? ?? 1b 1f 2b 1f 75 9d ?? ?? ?? ?? ?? 1b 1f 2c 1f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {16 1f 30 9d ?? ?? ?? ?? ?? 1b 17 1f 2e 9d ?? ?? ?? ?? ?? 1b 18 1f 35 9d ?? ?? ?? ?? ?? 1b 19 1f 2e 9d ?? ?? ?? ?? ?? 1b 1a 1f 30 9d ?? ?? ?? ?? ?? 1b 1b 1f 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AA_2147682146_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AA"
        threat_id = "2147682146"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 1f 7c 9d ?? 17 1f 27 9d ?? 18 1f 7c 9d ?? 19 1f 27 9d ?? 1a 1f 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {16 1f 5b 9d ?? 17 1f 65 9d ?? 18 1f 6e 9d ?? 19 1f 64 9d ?? 1a 1f 6f 9d ?? 1b 1f 66 9d ?? 1c 1f 5d}  //weight: 10, accuracy: Low
        $x_1_3 = {18 1f 35 9d ?? 19 1f 2e 9d ?? 1a 1f 30 9d ?? 1b 1f 45}  //weight: 1, accuracy: Low
        $x_1_4 = {17 1f 2e 9d ?? ?? ?? 00 00 18 1f 35 9d ?? ?? ?? 00 00 19 1f 2e 9d ?? ?? ?? 00 00 1a 1f 30 9d ?? 1b 1f 45}  //weight: 1, accuracy: Low
        $x_1_5 = {18 1f 35 9d ?? ?? ?? 00 00 19 1f 2e 9d ?? 1a 1f 30 9d ?? 1b 1f 45}  //weight: 1, accuracy: Low
        $x_10_6 = {1f 29 1f 5c 9d ?? 1f 2a 1f 52 9d ?? 1f 2b 1f 75 9d ?? 1f 2c 1f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AG_2147683161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AG"
        threat_id = "2147683161"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "KeyLogger" ascii //weight: 1
        $x_1_2 = "startupfixedR" ascii //weight: 1
        $x_1_3 = "%vn%" wide //weight: 1
        $x_1_4 = "0.5.5" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AH_2147683275_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AH"
        threat_id = "2147683275"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "njRAT.proc.resources" ascii //weight: 10
        $x_10_2 = "Builder.resources" ascii //weight: 10
        $x_10_3 = "njRAT.Chat.resources" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_CA_2147683343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.CA"
        threat_id = "2147683343"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[CyberSpread]" wide //weight: 1
        $x_1_2 = "[autorun]" wide //weight: 1
        $x_1_3 = "sendfile" wide //weight: 1
        $x_1_4 = "restart" ascii //weight: 1
        $x_1_5 = "usb_sp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_B_2147683424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.gen!B"
        threat_id = "2147683424"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "00444C56006E0047545600" wide //weight: 1
        $x_1_2 = "0053420053004253004200" wide //weight: 1
        $x_1_3 = "4D5A90" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AJ_2147683639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AJ"
        threat_id = "2147683639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|'|'|" wide //weight: 1
        $x_1_2 = "SGFjS2Vk" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_4 = "\" .." wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AJ_2147683639_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AJ"
        threat_id = "2147683639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00 61 76 69 63 61 70 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AJ_2147683639_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AJ"
        threat_id = "2147683639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 1d 0f 01 1a 28 ?? ?? 00 06 26}  //weight: 1, accuracy: Low
        $x_1_2 = {1f 1d 0f 00 1a 28 ?? ?? 00 06 26}  //weight: 1, accuracy: Low
        $x_10_3 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c 00}  //weight: 10, accuracy: High
        $x_10_4 = {00 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00 61 76 69 63 61 70 33 32 2e 64 6c 6c 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AJ_2147683639_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AJ"
        threat_id = "2147683639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 1d 0f 01 1a 28 05 00 (6f|28) ?? ?? 00 (0a|06|2b) ?? ?? ?? ?? ?? ?? ?? ?? 00 06 26}  //weight: 1, accuracy: Low
        $x_1_2 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00 61 76 69 63 61 70 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AJ_2147683639_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AJ"
        threat_id = "2147683639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 1d 0f 00 1a 28 05 00 (6f|28) ?? ?? 00 (0a|06|2b) ?? ?? ?? ?? ?? ?? ?? ?? 00 06 26}  //weight: 1, accuracy: Low
        $x_1_2 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00 61 76 69 63 61 70 33 32 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AJ_2147683639_5
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AJ"
        threat_id = "2147683639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "|'|'|" ascii //weight: 10
        $x_10_2 = {5b 45 4e 54 45 52 5d 0d 0a}  //weight: 10, accuracy: High
        $x_10_3 = {5b 54 41 50 5d 0d 0a}  //weight: 10, accuracy: High
        $x_10_4 = "netsh firewall add allowedprogram \"" ascii //weight: 10
        $x_1_5 = {63 6d 64 2e 65 78 65 20 2f ?? 20 70 69 6e 67 20 30 20 26 20 64 65 6c 20 22}  //weight: 1, accuracy: Low
        $x_1_6 = {63 6d 64 2e 65 78 65 20 2f ?? 20 70 69 6e 67 20 30 20 2d 6e 20 [0-4] 20 26 20 64 65 6c 20 22}  //weight: 1, accuracy: Low
        $x_1_7 = {63 6d 64 2e 65 78 65 20 2f ?? 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 26 20 64 65 6c 20 22}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AJ_2147683639_6
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AJ"
        threat_id = "2147683639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "|'|'|" wide //weight: 10
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_3 = "[ENTER]" wide //weight: 10
        $x_10_4 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c}  //weight: 10, accuracy: High
        $x_1_5 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 45 00 52 00 52 00 4f 00 52 00 [0-16] 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 45 00 52 00 52 00 4f 00 52 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 45 00 52 00 52 00 4f 00 52 00 [0-16] 45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 45 00 52 00 52 00 4f 00 52 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AJ_2147683639_7
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AJ"
        threat_id = "2147683639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "[endof]" wide //weight: 10
        $x_10_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 10
        $x_10_3 = "[ENTER]" wide //weight: 10
        $x_10_4 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c}  //weight: 10, accuracy: High
        $x_1_5 = {45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 45 00 52 00 52 00 4f 00 52 00 [0-16] 44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 45 00 52 00 52 00 4f 00 52 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 20 00 45 00 52 00 52 00 4f 00 52 00 [0-16] 45 00 78 00 65 00 63 00 75 00 74 00 65 00 20 00 45 00 52 00 52 00 4f 00 52 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AJ_2147683639_8
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AJ"
        threat_id = "2147683639"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "|'|'|" wide //weight: 10
        $x_10_2 = {5b 00 45 00 4e 00 54 00 45 00 52 00 5d 00 0d 00 0a 00}  //weight: 10, accuracy: High
        $x_10_3 = {5b 00 54 00 41 00 50 00 5d 00 0d 00 0a 00}  //weight: 10, accuracy: High
        $x_10_4 = "netsh firewall add allowedprogram \"" wide //weight: 10
        $x_1_5 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 ?? ?? 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_6 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 ?? ?? 20 00 70 00 69 00 6e 00 67 00 20 00 30 00 20 00 2d 00 6e 00 20 00 [0-8] 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 22 00}  //weight: 1, accuracy: Low
        $x_1_7 = {63 00 6d 00 64 00 2e 00 65 00 78 00 65 00 20 00 2f 00 ?? ?? 20 00 70 00 69 00 6e 00 67 00 20 00 31 00 32 00 37 00 2e 00 30 00 2e 00 30 00 2e 00 31 00 20 00 26 00 20 00 64 00 65 00 6c 00 20 00 22 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AK_2147683659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AK"
        threat_id = "2147683659"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 10 69 4c e4 41 60 d5 72 71 67 a2 d1 e4 03 3c 47 d4 04 4b fd 85 0d d2 6b b5 0a a5 fa a8 b5 35 6c 98 b2 42 d6 c9 bb db 40 f9 bc ac e3 6c d8 32}  //weight: 1, accuracy: High
        $x_1_2 = {20 35 46 4f 52 20 81 fb d3 62 20 47 81 87 3e 28}  //weight: 1, accuracy: High
        $x_1_3 = {59 26 68 d8 6a d8 d7 02 7b ?? ?? ?? ?? 03 6f}  //weight: 1, accuracy: Low
        $x_1_4 = "453D84A0B7580867248D1DD3CA522AE3" wide //weight: 1
        $x_1_5 = {53 65 72 76 65 72 2e 65 78 65 00 53 65 72 76 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AN_2147684087_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AN"
        threat_id = "2147684087"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 1d 0f 00 1a 28 ?? 00 00 06 26}  //weight: 10, accuracy: Low
        $x_1_2 = {09 20 a0 00 00 00 [0-48] 09 20 a1 00 00 00 [0-48] 09 20 00 00 01 00 [0-48] 09 1f 10 [0-48] 09 20 00 00 02 00 [0-48] 09 1f 11 [0-48] 09 20 a3 00 00 00}  //weight: 1, accuracy: Low
        $x_5_3 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_5_4 = {12 03 14 13 04 12 04 16 12 01 16 13 05 12 05 16 13 06 12 06 14 13 07 12 07 16 28 ?? 00 00 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AO_2147684088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AO"
        threat_id = "2147684088"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 1d 0f 01 1a 28 ?? 00 00 06 26}  //weight: 10, accuracy: Low
        $x_1_2 = {09 20 a0 00 00 00 [0-32] 09 20 a1 00 00 00 [0-32] 09 20 00 00 01 00 [0-32] 09 1f 10 [0-32] 09 20 00 00 02 00 [0-32] 09 1f 11 [0-32] 09 20 a3 00 00 00}  //weight: 1, accuracy: Low
        $x_5_3 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_5_4 = {12 03 14 13 04 12 04 16 12 01 16 13 05 12 05 16 13 06 12 06 14 13 07 12 07 16 28 ?? 00 00 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AL_2147684149_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AL"
        threat_id = "2147684149"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 1d 0f 01 1a 28 ?? 00 00 06 26}  //weight: 1, accuracy: Low
        $x_1_2 = {1f 1d 0f 00 1a 28 ?? 00 00 06 26}  //weight: 1, accuracy: Low
        $x_10_3 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 10, accuracy: Low
        $x_10_4 = {12 03 14 13 04 12 04 16 12 01 16 13 05 12 05 16 13 06 12 06 14 13 07 12 07 16 28 ?? 00 00 06}  //weight: 10, accuracy: Low
        $x_10_5 = {00 57 52 4b 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AP_2147684210_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AP"
        threat_id = "2147684210"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_2 = "capGetDriverDescriptionA" ascii //weight: 1
        $x_1_3 = "get_ShiftKeyDown" ascii //weight: 1
        $x_1_4 = "GetAsyncKeyState" ascii //weight: 1
        $x_10_5 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 10, accuracy: Low
        $x_1_6 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_7 = {53 00 45 00 45 00 5f 00 4d 00 41 00 53 00 4b 00 5f 00 4e 00 4f 00 5a 00 4f 00 4e 00 45 00 43 00 48 00 45 00 43 00 4b 00 53 00 [0-32] 63 00 6c 00 65 00 61 00 72 00 [0-8] 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00 [0-8] 63 00 6d 00 64 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AR_2147684257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AR"
        threat_id = "2147684257"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 1d 0f 01 1a 28 ?? 00 00 06}  //weight: 10, accuracy: Low
        $x_1_2 = {20 a0 00 00 00 [0-48] 20 a1 00 00 00 [0-48] 20 00 00 01 00 [0-48] 1f 10 [0-48] 20 00 00 02 00 [0-48] 1f 11 [0-48] 20 a3 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_4 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_5 = "capGetDriverDescriptionA" ascii //weight: 1
        $x_1_6 = "GetAsyncKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_DW_2147684796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.DW"
        threat_id = "2147684796"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 4e 74 53 65 74 49 6e 66 6f 72 6d 61 74 69 6f 6e 50 72 6f 63 65 73 73 00 6e 74 64 6c 6c 00 [0-32] 63 61 70 47 65 74 44 72 69 76 65 72 44 65 73 63 72 69 70 74 69 6f 6e 41 00 61 76 69 63 61 70 33 32 2e 64 6c 6c 00 [0-32] 47 65 74 56 6f 6c 75 6d 65 49 6e 66 6f 72 6d 61 74 69 6f 6e 41 00 6b 65 72 6e 65 6c 33 32 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AK_2147685723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AK!!Bladabindi"
        threat_id = "2147685723"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "Bladabindi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 10 69 4c e4 41 60 d5 72 71 67 a2 d1 e4 03 3c 47 d4 04 4b fd 85 0d d2 6b b5 0a a5 fa a8 b5 35 6c 98 b2 42 d6 c9 bb db 40 f9 bc ac e3 6c d8 32}  //weight: 1, accuracy: High
        $x_1_2 = {20 35 46 4f 52 20 81 fb d3 62 20 47 81 87 3e 28}  //weight: 1, accuracy: High
        $x_1_3 = {59 26 68 d8 6a d8 d7 02 7b ?? ?? ?? ?? 03 6f}  //weight: 1, accuracy: Low
        $x_1_4 = "453D84A0B7580867248D1DD3CA522AE3" wide //weight: 1
        $x_1_5 = {53 65 72 76 65 72 2e 65 78 65 00 53 65 72 76 65 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AA_2147685724_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AA!!Bladabindi"
        threat_id = "2147685724"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "Bladabindi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 1f 7c 9d ?? ?? ?? ?? ?? 1b 17 1f 27 9d ?? ?? ?? ?? ?? 1b 18 1f 7c 9d ?? ?? ?? ?? ?? 1b 19 1f 27 9d ?? ?? ?? ?? ?? 1b 1a 1f 7c}  //weight: 1, accuracy: Low
        $x_1_2 = {16 1f 5b 9d ?? ?? ?? ?? ?? 1b 17 1f 65 9d ?? ?? ?? ?? ?? 1b 18 1f 6e 9d ?? ?? ?? ?? ?? 1b 19 1f 64 9d ?? ?? ?? ?? ?? 1b 1a 1f 6f 9d ?? ?? ?? ?? ?? 1b 1b 1f 66 9d ?? ?? ?? ?? ?? 1b 1c 1f 5d}  //weight: 1, accuracy: Low
        $x_1_3 = {1f 29 1f 5c 9d ?? ?? ?? ?? ?? 1b 1f 2a 1f 52 9d ?? ?? ?? ?? ?? 1b 1f 2b 1f 75 9d ?? ?? ?? ?? ?? 1b 1f 2c 1f 6e}  //weight: 1, accuracy: Low
        $x_1_4 = {16 1f 30 9d ?? ?? ?? ?? ?? 1b 17 1f 2e 9d ?? ?? ?? ?? ?? 1b 18 1f 35 9d ?? ?? ?? ?? ?? 1b 19 1f 2e 9d ?? ?? ?? ?? ?? 1b 1a 1f 30 9d ?? ?? ?? ?? ?? 1b 1b 1f 45}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AA_2147685724_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AA!!Bladabindi"
        threat_id = "2147685724"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "Bladabindi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {16 1f 7c 9d ?? 17 1f 27 9d ?? 18 1f 7c 9d ?? 19 1f 27 9d ?? 1a 1f 7c}  //weight: 10, accuracy: Low
        $x_10_2 = {16 1f 5b 9d ?? 17 1f 65 9d ?? 18 1f 6e 9d ?? 19 1f 64 9d ?? 1a 1f 6f 9d ?? 1b 1f 66 9d ?? 1c 1f 5d}  //weight: 10, accuracy: Low
        $x_1_3 = {18 1f 35 9d ?? 19 1f 2e 9d ?? 1a 1f 30 9d ?? 1b 1f 45}  //weight: 1, accuracy: Low
        $x_1_4 = {17 1f 2e 9d ?? ?? ?? 00 00 18 1f 35 9d ?? ?? ?? 00 00 19 1f 2e 9d ?? ?? ?? 00 00 1a 1f 30 9d ?? 1b 1f 45}  //weight: 1, accuracy: Low
        $x_1_5 = {18 1f 35 9d ?? ?? ?? 00 00 19 1f 2e 9d ?? 1a 1f 30 9d ?? 1b 1f 45}  //weight: 1, accuracy: Low
        $x_10_6 = {1f 29 1f 5c 9d ?? 1f 2a 1f 52 9d ?? 1f 2b 1f 75 9d ?? 1f 2c 1f}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_B_2147685725_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.gen!B!!Bladabindi"
        threat_id = "2147685725"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "Bladabindi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "00444C56006E0047545600" wide //weight: 1
        $x_1_2 = "0053420053004253004200" wide //weight: 1
        $x_1_3 = "4D5A90" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AN_2147685726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AN!!Bladabindi"
        threat_id = "2147685726"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "Bladabindi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 1d 0f 00 1a 28 ?? 00 00 06 26}  //weight: 10, accuracy: Low
        $x_1_2 = {09 20 a0 00 00 00 [0-48] 09 20 a1 00 00 00 [0-48] 09 20 00 00 01 00 [0-48] 09 1f 10 [0-48] 09 20 00 00 02 00 [0-48] 09 1f 11 [0-48] 09 20 a3 00 00 00}  //weight: 1, accuracy: Low
        $x_5_3 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_5_4 = {12 03 14 13 04 12 04 16 12 01 16 13 05 12 05 16 13 06 12 06 14 13 07 12 07 16 28 ?? 00 00 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AO_2147685727_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AO!!Bladabindi"
        threat_id = "2147685727"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "Bladabindi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "21"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 1d 0f 01 1a 28 ?? 00 00 06 26}  //weight: 10, accuracy: Low
        $x_1_2 = {09 20 a0 00 00 00 [0-32] 09 20 a1 00 00 00 [0-32] 09 20 00 00 01 00 [0-32] 09 1f 10 [0-32] 09 20 00 00 02 00 [0-32] 09 1f 11 [0-32] 09 20 a3 00 00 00}  //weight: 1, accuracy: Low
        $x_5_3 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 5, accuracy: Low
        $x_5_4 = {12 03 14 13 04 12 04 16 12 01 16 13 05 12 05 16 13 06 12 06 14 13 07 12 07 16 28 ?? 00 00 06}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AL_2147685728_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AL!!Bladabindi"
        threat_id = "2147685728"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "Bladabindi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 1d 0f 01 1a 28 ?? 00 00 06 26}  //weight: 1, accuracy: Low
        $x_1_2 = {1f 1d 0f 00 1a 28 ?? 00 00 06 26}  //weight: 1, accuracy: Low
        $x_10_3 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 10, accuracy: Low
        $x_10_4 = {12 03 14 13 04 12 04 16 12 01 16 13 05 12 05 16 13 06 12 06 14 13 07 12 07 16 28 ?? 00 00 06}  //weight: 10, accuracy: Low
        $x_10_5 = {00 57 52 4b 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AP_2147685729_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AP!!Bladabindi"
        threat_id = "2147685729"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "Bladabindi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_2 = "capGetDriverDescriptionA" ascii //weight: 1
        $x_1_3 = "get_ShiftKeyDown" ascii //weight: 1
        $x_1_4 = "GetAsyncKeyState" ascii //weight: 1
        $x_10_5 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 10, accuracy: Low
        $x_1_6 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AR_2147685730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AR!!Bladabindi"
        threat_id = "2147685730"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "Bladabindi: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "14"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {1f 1d 0f 01 1a 28 ?? 00 00 06}  //weight: 10, accuracy: Low
        $x_1_2 = {20 a0 00 00 00 [0-48] 20 a1 00 00 00 [0-48] 20 00 00 01 00 [0-48] 1f 10 [0-48] 20 00 00 02 00 [0-48] 1f 11 [0-48] 20 a3 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {1f 64 14 13 04 12 04 1f 64 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_4 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_5 = "capGetDriverDescriptionA" ascii //weight: 1
        $x_1_6 = "GetAsyncKeyState" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AV_2147686235_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AV"
        threat_id = "2147686235"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "bmV0c2ggZmlyZXdhbGwgYWRkIGFsbG93ZWRwcm9ncmFtICI=" wide //weight: 1
        $x_1_2 = "Y21kLmV4ZSAvayBwaW5nIDAgJiBkZWwgIg==" wide //weight: 1
        $x_1_3 = {1f 1d 0f 01 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_4 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_D_2147686741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.gen!D"
        threat_id = "2147686741"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NJServer" ascii //weight: 1
        $x_1_2 = "RSMDecrypt" ascii //weight: 1
        $x_1_3 = "NJCrypte" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_E_2147686942_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.gen!E"
        threat_id = "2147686942"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NJServer.MDIParent1.resources" ascii //weight: 1
        $x_1_2 = "Devencryption" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AX_2147688659_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AX"
        threat_id = "2147688659"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {6e 6a 4c 6f 67 67 65 72 00}  //weight: 2, accuracy: High
        $x_2_2 = {41 6e 74 69 54 61 73 6b 4d 61 6e 61 67 65 72 00}  //weight: 2, accuracy: High
        $x_1_3 = {00 45 4e 42 00 44 45 42 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 44 4c 56 00 47 54 56 00 53 54 56 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AY_2147688975_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AY"
        threat_id = "2147688975"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {00 44 4c 56 00 6e 00 47 54 56 00 53 54 56 00}  //weight: 10, accuracy: High
        $x_10_2 = {00 45 4e 42 00 73 00 44 45 42 00}  //weight: 10, accuracy: High
        $x_1_3 = "AntiAvira" ascii //weight: 1
        $x_1_4 = "UpdateServerByDownload" ascii //weight: 1
        $x_1_5 = "CheckIfKillSomeProcesses" ascii //weight: 1
        $x_1_6 = "AntiVirtualUsingWMI" ascii //weight: 1
        $x_1_7 = "AVGSuspend" ascii //weight: 1
        $x_1_8 = "BlockSite_IE_FF_Chrome" ascii //weight: 1
        $x_1_9 = {00 6b 6c 00 6c 6f 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_BC_2147690390_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BC"
        threat_id = "2147690390"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 44 4c 56 00 6e 00 47 54 56 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 42 00 53 00 42 53 00 42 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 4c 61 73 74 41 56 00 4c 61 73 74 41 53 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 55 4e 53 00 49 4e 53 00 49 6e 64 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 6b 00 57 52 4b 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 47 65 74 4b 65 79 00 6b 65 79 00 70 72 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 47 65 74 41 73 79 6e 63 4b 65 79 53 74 61 74 65 00 57 52 4b 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_BE_2147695319_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BE"
        threat_id = "2147695319"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "RunPE" ascii //weight: 1
        $x_1_2 = "[ENTER]" wide //weight: 1
        $x_1_3 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_1_4 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_BF_2147695408_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BF"
        threat_id = "2147695408"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "7#C#0#0#2#7#0#0#7#C#0#0#2#7#0#0#7#C#" wide //weight: 1
        $x_1_2 = "5#B#0#0#4#5#0#0#4#E#0#0#5#4#0#0#4#5#0#0#5#2#0#0#5#D#" wide //weight: 1
        $x_1_3 = "4#4#4#C#5#6#0#0#6#E#0#0#4#7#5#4#5#6#" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_BG_2147695500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BG"
        threat_id = "2147695500"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {38 00 34 00 ?? ?? 38 00 36 00 ?? ?? 31 00 31 00 33 00 ?? ?? 38 00 31 00 ?? ?? 36 00 35 00}  //weight: 1, accuracy: Low
        $x_1_2 = {36 00 35 00 ?? ?? 36 00 39 00 ?? ?? 38 00 35 00 ?? ?? 36 00 35 00 ?? ?? 38 00 34 00 ?? ?? 31 00 30 00 33 00 ?? ?? 36 00 36 00 ?? ?? 38 00 35 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_BI_2147708027_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BI"
        threat_id = "2147708027"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|'|'|" wide //weight: 1
        $x_1_2 = "[ENTER]" wide //weight: 1
        $x_1_3 = "[kl]" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_BJ_2147708045_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BJ"
        threat_id = "2147708045"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "schtasks /create /sc minute /mo 1 /tn igfxTrays /tr" wide //weight: 2
        $x_1_2 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_3 = {1f 1d 0f 01 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_BK_2147716100_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BK"
        threat_id = "2147716100"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 49 4e 44 00 62 00 49 4e 46 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 53 65 6e 64 00 53 00 43 4e 00 52 43 00 41 53 74 61 72 74 75 70 00}  //weight: 1, accuracy: High
        $x_1_3 = {00 48 57 44 00 42 53 00 53 42 00}  //weight: 1, accuracy: High
        $x_1_4 = {00 57 52 44 00 53 50 4c 00}  //weight: 1, accuracy: High
        $x_1_5 = "|fb|" wide //weight: 1
        $x_1_6 = "sendesktop" wide //weight: 1
        $x_1_7 = "\\hell.png" wide //weight: 1
        $x_1_8 = "[mqo-zz]" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_BL_2147717141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BL"
        threat_id = "2147717141"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "[endof]" wide //weight: 5
        $x_5_2 = "|'|'|" wide //weight: 5
        $x_1_3 = "[Me]" wide //weight: 1
        $x_1_4 = {42 53 00 42 00 44 45 42 00}  //weight: 1, accuracy: High
        $x_1_5 = {44 45 42 00 73 00 45 4e 42 00}  //weight: 1, accuracy: High
        $x_1_6 = {52 43 00 53 42 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_BM_2147720489_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BM"
        threat_id = "2147720489"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "|523|" wide //weight: 1
        $x_1_2 = "[endof]" wide //weight: 1
        $x_1_3 = "facebook-profile.redirectme.net" wide //weight: 1
        $x_1_4 = "SearchUi.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_OR_2147723965_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.OR"
        threat_id = "2147723965"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tniopyrtnE" wide //weight: 1
        $x_1_2 = "ekovnI" wide //weight: 1
        $x_2_3 = {17 17 8d 18 00 00 01 25 16 fe 0c 87 03 00 00 a2 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? fe 0e 8d 03 00 00 fe 0c 8d 03 00 00 28 ?? ?? ?? ?? fe 0c 89 03 00 00 28 ?? ?? ?? ?? 18 16 8d 18 00 00 01 28 ?? ?? ?? ?? 28 ?? ?? ?? ?? fe 0e 8e 03 00 00 fe 0c 8e 03 00 00 28 ?? ?? ?? ?? fe 0c 8a 03 00 00 28 ?? ?? ?? ?? 17 18 8d 18 00 00 01 28 ?? ?? ?? ?? 28}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_2147729738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi!MTB"
        threat_id = "2147729738"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {72 6d 0a 00 70 18 18 8d 25 00 00 01 25 16 08 8c 0d 00 00 01 a2 25 17 11 04 8c 0d 00 00 01 a2 28 94 00 00 0a a5 0a 00 00 01 13 05 11 05 16 16 16 16}  //weight: 1, accuracy: High
        $x_1_2 = {72 7f 0a 00 70 18 16 8d 25 00 00 01 28 94 00 00 0a a5 64 00 00 01 6f 97 00 00 0a 00 06 11 05 8c 0a 00 00 01 72 83 0a 00 70 18 16 8d 25 00 00 01 28 94 00 00 0a a5 64 00 00 01 6f 97 00 00 0a 00 06 11 05 8c 0a 00 00 01 72 87 0a 00 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_2147729738_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi!MTB"
        threat_id = "2147729738"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {28 17 00 00 2b 7e ?? 00 00 0a 8e 20 f8 cb 00 00 58 20 91 85 01 00 20 df 49 ff ff 58 20 4c 25 00 00 7e 0b 00 00 04 0b 07 5f 65 20 b2 08 00 00 59 07 1f 1d 62 07 20 00 00 00 28 5a 58}  //weight: 1, accuracy: Low
        $x_1_2 = {28 03 00 00 06 18 16 8d 11 00 00 01 20 ?? ?? 00 00 20 ?? ?? 00 00 28 19 00 00 2b 14 20 f1 25 a8 55 20 35 20 58 aa d6 7e ?? 00 00 0a 8e 20 3b 4a 00 00 58 7e ?? 00 00 0a 8e 20 83 00 00 00 58}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_2147729738_2
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi!MTB"
        threat_id = "2147729738"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CreateSubKey" ascii //weight: 1
        $x_1_2 = "set_UseShellExecute" ascii //weight: 1
        $x_1_3 = "set_CreateNoWindow" ascii //weight: 1
        $x_1_4 = "SetAccessRuleProtection" ascii //weight: 1
        $x_1_5 = "SetAccessControl" ascii //weight: 1
        $x_1_6 = "get_UserName" ascii //weight: 1
        $x_1_7 = "AddAccessRule" ascii //weight: 1
        $x_1_8 = "DownloadFile" ascii //weight: 1
        $x_1_9 = "get_EntryPoint" ascii //weight: 1
        $x_1_10 = "FromBase64String" ascii //weight: 1
        $x_11_11 = "CyaX-Sharp" ascii //weight: 11
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_11_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_2147729738_3
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi!MTB"
        threat_id = "2147729738"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "processInformation" ascii //weight: 1
        $x_1_2 = "VKCodeToUnicode" ascii //weight: 1
        $x_1_3 = "ServerComputer" ascii //weight: 1
        $x_1_4 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_5 = "zzz;VVVxAAA" ascii //weight: 1
        $x_1_6 = "get_CapsLock" ascii //weight: 1
        $x_1_7 = "get_MainWindowTitle" ascii //weight: 1
        $x_1_8 = "get_ServicePack" ascii //weight: 1
        $x_1_9 = "CopyFromScreen" ascii //weight: 1
        $x_1_10 = "GetKeyboardState" ascii //weight: 1
        $x_1_11 = "ParameterizedThreadStart" ascii //weight: 1
        $x_1_12 = "System.Net.Sockets" ascii //weight: 1
        $x_1_13 = "get_ShiftKeyDown" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_2147729738_4
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi!MTB"
        threat_id = "2147729738"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ServerComputer" ascii //weight: 1
        $x_1_2 = "get_Registry" ascii //weight: 1
        $x_1_3 = "get_CurrentUser" ascii //weight: 1
        $x_1_4 = "DownloadFile" ascii //weight: 1
        $x_1_5 = "set_UseShellExecute" ascii //weight: 1
        $x_1_6 = "set_FileName" ascii //weight: 1
        $x_1_7 = "set_WindowStyle" ascii //weight: 1
        $x_1_8 = "ProcessWindowStyle" ascii //weight: 1
        $x_1_9 = "GetAntivirus" ascii //weight: 1
        $x_1_10 = "System.Net.Sockets" ascii //weight: 1
        $x_1_11 = "\\worms\\." wide //weight: 1
        $x_1_12 = "[NOREG]" wide //weight: 1
        $x_1_13 = "[NOSTUP]" wide //weight: 1
        $x_1_14 = "[pastebinn]" wide //weight: 1
        $x_1_15 = "root\\SecurityCenter" wide //weight: 1
        $x_1_16 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_17 = "ddosstop" wide //weight: 1
        $x_1_18 = "openhide" wide //weight: 1
        $x_1_19 = "SELECT * FROM AntiVirusProduct" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_OS_2147733005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.OS!bit"
        threat_id = "2147733005"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hmzaVAR" wide //weight: 1
        $x_1_2 = "82.137.255.56" wide //weight: 1
        $x_1_3 = "</HAMZA_DELIMITER_STOP>" wide //weight: 1
        $x_1_4 = {53 76 68 6f 73 74 36 34 2e 48 6d 7a 61 00 48 6d 7a 61 50 61 63 6b 65 74}  //weight: 1, accuracy: High
        $x_1_5 = "Svhost64.Utility" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AD_2147733704_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AD!bit"
        threat_id = "2147733704"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 da 91 1f 70 61 04 00 03 03 8e}  //weight: 1, accuracy: Low
        $x_1_2 = {07 11 05 03 11 05 91 06 61 09 08 91 61}  //weight: 1, accuracy: High
        $x_1_3 = {58 4f 52 5f 44 45 43 00 50 31 00 4b 31}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_BT_2147733925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BT!bit"
        threat_id = "2147733925"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Njrat 0.7 Golden" wide //weight: 3
        $x_1_2 = "Select * From AntiVirusProduct" wide //weight: 1
        $x_1_3 = "www.upload.ee/image/2298158/koli.swf" wide //weight: 1
        $x_1_4 = "[PrintScreen]" wide //weight: 1
        $x_1_5 = "ReverseMouse" wide //weight: 1
        $x_1_6 = "schtasks /create /sc minute /mo 1 /tn Server /tr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_BU_2147735907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BU!bit"
        threat_id = "2147735907"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 4f 4b 00 4d 65 4d 00}  //weight: 1, accuracy: High
        $x_1_2 = {00 48 57 44 00 45 58 45 00}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\Users\\NO_LOVINO\\" ascii //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_PA_2147742837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.PA!MTB"
        threat_id = "2147742837"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TypeScript Keyboard Sync.exe" ascii //weight: 1
        $x_1_2 = "ONIOZLZLWNJTPUPLYMBFCGBQFIQDZVDGN" wide //weight: 1
        $x_1_3 = "get_DGGHD04AV2ENU2K6VB0" ascii //weight: 1
        $x_1_4 = "get_AOORSRDYO3OQPNHD83" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_BP_2147743251_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BP!MSR"
        threat_id = "2147743251"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "USBSpreader" ascii //weight: 1
        $x_1_2 = "get_keylog" ascii //weight: 1
        $x_1_3 = "keylog_KeyPressed" ascii //weight: 1
        $x_1_4 = "MasterAdvancedKeylogger" ascii //weight: 1
        $x_1_5 = "KeeeeeyLog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SM_2147745469_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SM!MTB"
        threat_id = "2147745469"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 1f 1a 0b 1f 4e 0c 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 6f ?? ?? ?? ?? 0d 09 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 04 73 ?? ?? ?? ?? 13 05 11 04 17 8d ?? ?? ?? ?? 25 16 11 05 6f ?? ?? ?? ?? a2 28 ?? ?? ?? ?? 26 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SM_2147745469_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SM!MTB"
        threat_id = "2147745469"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 06 07 06 93 02 7b 03 00 00 04 04 20 3b ad 23 26 20 ca 4e a1 27 61 66 66 20 d9 d0 64 d1 61 65 65 20 d5 83 e8 4d 61 66 20 e4 3b 46 be 61 66 20 16 8b 48 23 61 5f 91 04 60 61 d1 9d}  //weight: 2, accuracy: High
        $x_2_2 = "33333333.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MMS_2147745627_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MMS!MTB"
        threat_id = "2147745627"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0a a2 25 1f 0b 11 0b a2 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 0c 11 0c 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 0d 11 0d 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 0e 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 0e 6f ?? ?? ?? ?? 14 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MMC_2147746117_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MMC!MTB"
        threat_id = "2147746117"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {1f 0b 11 0b a2 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 0c 2b 06 0b 38 ?? ?? ?? ?? 11 0c 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 0d 2b 06 0a 38 ?? ?? ?? ?? 11 0d 20 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 0e 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 0e 6f ?? ?? ?? ?? 14 17}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MI_2147748449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MI!MTB"
        threat_id = "2147748449"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0b 06 07 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0c 08 6f ?? ?? ?? ?? 16 9a 0d 09 6f ?? ?? ?? ?? 16 9a 13 04 73 ?? ?? ?? ?? ?? ?? ?? ?? ?? 11 04 14 1f 09 8d ?? ?? ?? ?? 25 16}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SA_2147748516_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SA!MSR"
        threat_id = "2147748516"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "led & 2 n- 0 gnip c/ exe.dmc" wide //weight: 1
        $x_1_2 = "margorpdewolla eteled llawerif hsten" wide //weight: 1
        $x_2_3 = "nuR\\\\noisreVtnerruC\\\\swodniW\\\\tfosorciM\\\\erawtfoS" wide //weight: 2
        $x_2_4 = "emoloveemomoody55.d2dns.net" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_MOB_2147750263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MOB!MTB"
        threat_id = "2147750263"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 0c 06 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 09 72 ?? ?? ?? ?? ?? ?? ?? ?? ?? 13 04 11 04 14 72 ?? ?? ?? ?? 18 8d ?? ?? ?? ?? 25 17 17 8d ?? ?? ?? ?? 25 16 08 6f ?? ?? ?? ?? a2 a2 14 14 28 ?? ?? ?? ?? ?? 1f 49 13 05 2b 00 11 05 2a 1e 00 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 1b 73 ?? ?? ?? ?? 0b 07}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MLB_2147750264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MLB!MTB"
        threat_id = "2147750264"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 14 72 ?? ?? ?? ?? 18 8d ?? ?? ?? ?? 25 17 17 8d ?? ?? ?? ?? 25 16 17 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 a2 a2 14 14 14 28 ?? ?? ?? ?? 26 0c 00 ?? 02}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MPJ_2147750843_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MPJ!MTB"
        threat_id = "2147750843"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {13 06 11 06 28 ?? ?? ?? ?? 0c 08 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 0d 09 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? 16 8c ?? ?? ?? ?? 14 6f ?? ?? ?? ?? 26 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MSD_2147751379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MSD!MTB"
        threat_id = "2147751379"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 9a 0b 02 07 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2a 16 00 28 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 0a 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MX_2147753571_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MX!MTB"
        threat_id = "2147753571"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {17 9a 0a 06 14 18 8d ?? ?? ?? ?? 25 16 7e ?? ?? ?? ?? a2 25 17 72 95 01 00 70 a2 6f ?? ?? ?? ?? 26 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_PC_2147754501_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.PC!MTB"
        threat_id = "2147754501"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Anti_avast" ascii //weight: 1
        $x_1_2 = "Anti_Kaspersky" ascii //weight: 1
        $x_1_3 = "WriteProcessMemory" ascii //weight: 1
        $x_1_4 = "LoadFile" ascii //weight: 1
        $x_1_5 = "inject" ascii //weight: 1
        $x_1_6 = "MinstoreEvents.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SBR_2147756301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SBR!MSR"
        threat_id = "2147756301"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 06 26 28 [0-2] 00 06 28 08 00 00 0a 72 [0-2] 00 70 28 [0-2] 00 06 28 08 00 00 0a 28 10 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 06 26 28 [0-2] 00 06 28 07 00 00 0a 0b 28 [0-2] 00 06 28 08 00 00 0a 0c 18 0d 18 8d 01 00 00 01 13 04 11 04 16 28 [0-2] 00 06 a2 07 08 09 11 04 28 09 00 00 0a 2a}  //weight: 1, accuracy: Low
        $x_1_3 = "GetDomain" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SBR_2147756301_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SBR!MSR"
        threat_id = "2147756301"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 0b 00 00 04 28 20 00 00 0a 72 ?? 00 00 70 7e 0a 00 00 04 28 21 00 00 0a 0b 28 04 00 00 06 6f 22 00 00 0a 07 6f 23 00 00 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {20 d0 07 00 00 28 2f 00 00 0a 1f 1c 28 5a 00 00 0a 72 ?? 03 00 70 28 1e 00 00 0a 80 13 00 00 04 7e 13 00 00 04 72 ?? 03 00 70 28 1e 00 00 0a 28 55 00 00 0a 7e 0e 00 00 04 72 ?? 03 00 70 7e 0c 00 00 04 72 ?? 00 00 70 28 21 00 00 0a 6f 27 00 00 06 de 2c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_PD_2147756392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.PD!MTB"
        threat_id = "2147756392"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 01 00 00 70 28 ?? ?? 00 0a 73 04 00 00 0a 0a 1f 1c 28 05 00 00 0a 72 0d 00 00 70 28 06 00 00 0a 06 72 2b 00 00 70 6f 07 00 00 0a 74 01 00 00 1b 28 08 00 00 0a 1f 1c 28 05 00 00 0a 72 0d 00 00 70 28 06 00 00 0a 28 09 00 00 0a 26 1f 1c 28 05 00 00 0a 72 41 00 00 70 28 06 00 00 0a 06 72 ?? ?? 00 70 6f 07 00 00 0a 74 01 00 00 1b 28 08 00 00 0a 1f 1c 28 05 00 00 0a 72 41 00 00 70 28 06 00 00 0a 28 09 00 00 0a 26 de}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AF_2147759718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AF!MTB"
        threat_id = "2147759718"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReadSquad" ascii //weight: 1
        $x_1_2 = "TVqQ,M,,E,,//8,Lg,,,,AQ,,,,,,,,,,,,,,,,,,,,,,,Ag,,A4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJ" ascii //weight: 1
        $x_1_3 = "TVqQAAM,,E,,AA,E,,//8AAE,,//8,LgAA,//8,Lg,,," wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AA_2147765389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AA!MTB"
        threat_id = "2147765389"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "19"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {06 11 0f 18 64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 e0 91 1f 10 62 60 07 11 0e 11 0f 17 58 58 e0 91 1e 62 60 07 11 0e 11 0f 58 e0 91 60 9e 11 0f 1a 58 13 0f 11 0f 1f 3d 44 b9 ff ff ff}  //weight: 10, accuracy: High
        $x_3_2 = "SimpleDetector" ascii //weight: 3
        $x_3_3 = "System.Net.NetworkInformation" ascii //weight: 3
        $x_3_4 = "RSACryptoServiceProvider" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AA_2147765389_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AA!MTB"
        threat_id = "2147765389"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Covid.exe" ascii //weight: 1
        $x_1_2 = "Injection_DoWork" ascii //weight: 1
        $x_1_3 = "hacking tool" ascii //weight: 1
        $x_1_4 = "See Ghosts Chat" ascii //weight: 1
        $x_1_5 = "55 8B EC 80 3D 05 61 BC 63 00" ascii //weight: 1
        $x_1_6 = "https://hastebin.com/raw/maruzucehi" ascii //weight: 1
        $x_1_7 = "http://www.gustabf.tk/update.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_VPL_2147772034_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.VPL!MTB"
        threat_id = "2147772034"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MBTMoIoGXAgKkAiyYkCTRqHSXlHG" ascii //weight: 1
        $x_1_2 = "szHSnbcBiCQzrhHzExKvktAqdIdL" ascii //weight: 1
        $x_1_3 = "rMTyAdbEmKqHqvoEMjtJvjNLOmzb" ascii //weight: 1
        $x_1_4 = "qhBKDCzWlrGjyKRvQsmzZBZdTnRE" ascii //weight: 1
        $x_1_5 = "QsOGfGBcMFTyyaEfSdxkULvZmXlX" ascii //weight: 1
        $x_1_6 = "mYXYIJRCCdWGtsUApWSfXsEfVRml" ascii //weight: 1
        $x_1_7 = "dFMjkuSkuCGuFfUilWzIaqNKxtcgA" ascii //weight: 1
        $x_1_8 = "ToBase64String" ascii //weight: 1
        $x_1_9 = "RijndaelManaged" ascii //weight: 1
        $x_1_10 = "$31e6340c-0529-4c33-88bc-8e79fda31733" ascii //weight: 1
        $x_1_11 = "w3wp.exe" wide //weight: 1
        $x_1_12 = "aspnet_wp.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_GA_2147773584_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.GA!MTB"
        threat_id = "2147773584"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "victimName" ascii //weight: 1
        $x_1_2 = "keylogger" ascii //weight: 1
        $x_1_3 = "isConnected" ascii //weight: 1
        $x_1_4 = "Monitor" ascii //weight: 1
        $x_1_5 = "TcpClient" ascii //weight: 1
        $x_1_6 = "DownloadData" ascii //weight: 1
        $x_1_7 = "Plugin" ascii //weight: 1
        $x_1_8 = "CopyFromScreen" ascii //weight: 1
        $x_1_9 = "Uninstall" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_GA_2147773584_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.GA!MTB"
        threat_id = "2147773584"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 07 16 73 ?? ?? ?? 0a 0c 1a 8d ?? ?? ?? 01 0d 07 07 6f ?? ?? ?? 0a 1b 6a da 6f ?? ?? ?? 0a 00 07 09 16 1a 6f ?? ?? ?? 0a 26 09 16 28 ?? ?? ?? 0a 13 04 07 16 6a 6f ?? ?? ?? 0a 00 11 04 17 da 17 d6 17 da 17 d6 17 da 17 d6 8d ?? ?? ?? 01 13 05 08 11 05 16 11 04 6f ?? ?? ?? 0a 26 08 6f ?? ?? ?? 0a 00 07 6f ?? ?? ?? 0a 00 11 05 0a 2b 00 06 2a}  //weight: 10, accuracy: Low
        $x_1_2 = "GetFolderPath" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_RH_2147774344_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.RH!MTB"
        threat_id = "2147774344"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "file:///" wide //weight: 1
        $x_1_2 = "{11111-22222-40001-00001}" wide //weight: 1
        $x_1_3 = "{11111-22222-40001-00002}" wide //weight: 1
        $x_1_4 = "{11111-22222-50001-00000}" wide //weight: 1
        $x_10_5 = "$d2a142bb-b24e-422c-a5ec-ef4d81e0a1e6" ascii //weight: 10
        $x_1_6 = "ServerComputer" ascii //weight: 1
        $x_1_7 = "get_FileSystem" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_ALE_2147781618_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ALE!MTB"
        threat_id = "2147781618"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {08 17 d6 0c 08 1a fe 02 0d 09 2c 02 de 5d 00 00 14 0b 08 b5 1f 64 28 28 00 00 0a 13 05 12 05 1f 64 12 01 1f 64 28 0d 00 00 06 16 fe 01 13 04 11 04 2c 02 2b ca}  //weight: 10, accuracy: High
        $x_3_2 = "No-Love" ascii //weight: 3
        $x_3_3 = "capGetDriverDescriptionA" ascii //weight: 3
        $x_3_4 = "cmd.exe /c ping 0 -n 2 & del" ascii //weight: 3
        $x_3_5 = "Moe1" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_WA_2147781884_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.WA!MTB"
        threat_id = "2147781884"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {01 0b 11 04 11 04 6f ?? ?? ?? 0a 1b 6a da 6f ?? ?? ?? 0a 11 04 07 16 1a 6f ?? ?? ?? 0a 26 07 16 28 ?? ?? ?? 0a 0c 11 04 16 6a 6f ?? ?? ?? 0a 08 17 da 17 d6 17 da 17 d6 17 da 17 d6 8d ?? ?? ?? 01 0a 09 06 16 08 6f ?? ?? ?? 0a 26 09}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "ToArray" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_MSIL_Bladabindi_AM_2147782678_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AM!MTB"
        threat_id = "2147782678"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0d 09 2c 4e 09 6f ?? ?? ?? ?? 0a 06 7e ?? ?? ?? ?? 28 ?? ?? ?? ?? 2d 1c 06 7e ?? ?? ?? ?? 28 ?? ?? ?? ?? 2d 17 06 7e ?? ?? ?? ?? 28 ?? ?? ?? ?? 2d 12 2b 18 7e ?? ?? ?? ?? 0b 2b 16 7e ?? ?? ?? ?? 0b 2b 0e 7e ?? ?? ?? ?? 0b 2b 06}  //weight: 10, accuracy: Low
        $x_3_2 = "defaultBrowser" ascii //weight: 3
        $x_3_3 = "GetInstalledBrowser" ascii //weight: 3
        $x_3_4 = "showIn_special_Browser" ascii //weight: 3
        $x_3_5 = "Is64Bits" ascii //weight: 3
        $x_3_6 = "IsWow64Process" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_GG_2147788929_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.GG!MTB"
        threat_id = "2147788929"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "njStub" ascii //weight: 1
        $x_1_2 = "CompressionMode" ascii //weight: 1
        $x_1_3 = "HttpWebResponse" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
        $x_1_5 = "get_ExecutablePath" ascii //weight: 1
        $x_1_6 = "CopyFromScreen" ascii //weight: 1
        $x_1_7 = "get_Position" ascii //weight: 1
        $x_1_8 = "DecompressGzip" ascii //weight: 1
        $x_1_9 = "HiddenStartup" ascii //weight: 1
        $x_1_10 = "NtSetInformationProcess" ascii //weight: 1
        $x_1_11 = "\\Documents\\dllhost /f" ascii //weight: 1
        $x_1_12 = "cmd.exe /C Y /N /D Y /T 1 & Del" ascii //weight: 1
        $x_1_13 = "Download ERROR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_QM_2147794688_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.QM!MTB"
        threat_id = "2147794688"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1c 13 09}  //weight: 10, accuracy: High
        $x_3_2 = "temp\\Assembly.exe" ascii //weight: 3
        $x_3_3 = "ObfuscationAttribute" ascii //weight: 3
        $x_3_4 = "StripAfterObfuscation" ascii //weight: 3
        $x_3_5 = "YanoAttribute" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_DF_2147809384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.DF!MTB"
        threat_id = "2147809384"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "21"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Esyybfsfz.Properties.Resources" ascii //weight: 3
        $x_3_2 = "oHc3y9UaAW" ascii //weight: 3
        $x_3_3 = "LogoutProperty" ascii //weight: 3
        $x_3_4 = "DebuggerHiddenAttribute" ascii //weight: 3
        $x_3_5 = "MD5CryptoServiceProvider" ascii //weight: 3
        $x_3_6 = "TripleDESCryptoServiceProvider" ascii //weight: 3
        $x_3_7 = "set_Key" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KR_2147817575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KR!MTB"
        threat_id = "2147817575"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 08 03 6f ?? ?? ?? 0a 5d 17 d6 28 ?? ?? ?? 0a da 0d 06 09 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 2b 00 02 08 28}  //weight: 1, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "AppDomain" ascii //weight: 1
        $x_1_4 = "CurrentDomain" ascii //weight: 1
        $x_1_5 = "EntryPoint" ascii //weight: 1
        $x_1_6 = "Conversions" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KS_2147817576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KS!MTB"
        threat_id = "2147817576"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 18 18 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 13 ?? 11 ?? 14 72 24 00 28 ?? ?? ?? 0a 02 11}  //weight: 1, accuracy: Low
        $x_1_2 = "CipherMode" ascii //weight: 1
        $x_1_3 = "PaddingMode" ascii //weight: 1
        $x_1_4 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KT_2147818435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KT!MTB"
        threat_id = "2147818435"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 1f 1a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 22 00 73 ?? ?? ?? 0a 0a 06 72}  //weight: 1, accuracy: Low
        $x_1_2 = {0a 0b 07 2a 2a 00 1f 1a 28 ?? ?? ?? 0a 72 ?? ?? ?? 70 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0a 06 72}  //weight: 1, accuracy: Low
        $x_1_3 = "FromBase64String" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ESG_2147818841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ESG!MTB"
        threat_id = "2147818841"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$73c3cacb-299e-48bc-a9b6-6381eb8acd1f" ascii //weight: 1
        $x_1_2 = "GTBit_Beta_" wide //weight: 1
        $x_1_3 = "Growtopia.exe" wide //weight: 1
        $x_1_4 = {00 4c 61 75 6e 63 68 47 72 6f 77 74 6f 70 69 61 00}  //weight: 1, accuracy: High
        $x_1_5 = {00 52 65 63 6f 72 64 4d 6f 75 73 65 43 6c 69 63 6b 00}  //weight: 1, accuracy: High
        $x_1_6 = {00 55 6e 68 6f 6f 6b 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 00}  //weight: 1, accuracy: High
        $x_1_7 = {00 53 65 74 57 69 6e 64 6f 77 73 48 6f 6f 6b 45 78 00}  //weight: 1, accuracy: High
        $x_1_8 = {00 53 65 74 46 6f 72 65 67 72 6f 75 6e 64 57 69 6e 64 6f 77 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_CG_2147818860_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.CG!MTB"
        threat_id = "2147818860"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {11 0e 11 0f 9a 13 05 09 11 05 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 13 06 12 04 11 04 8e 69 11 06 8e 69 58 28}  //weight: 1, accuracy: Low
        $x_1_2 = {11 06 16 11 04 11 04 8e 69 11 06 8e 69 59 11 06 8e 69 28 ?? ?? ?? 0a 11 0f 17 58 13 0f 11 0f 11 0e 8e 69 32}  //weight: 1, accuracy: Low
        $x_2_3 = "AAhvUE4rEQTdIaoQ5jS" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ER_2147820473_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ER!MTB"
        threat_id = "2147820473"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MD5CryptoServiceProvider" ascii //weight: 1
        $x_1_2 = "System.Net.Sockets" ascii //weight: 1
        $x_1_3 = "hookID" ascii //weight: 1
        $x_1_4 = "KEYEVENTF_EXTENDEDKEY" ascii //weight: 1
        $x_1_5 = "AES_Decrypt" ascii //weight: 1
        $x_1_6 = "Slowloris Attack is Already Running on" wide //weight: 1
        $x_1_7 = "ARME Attack is Already Running on" wide //weight: 1
        $x_1_8 = "AntiProcess: Process Hacker was detected!" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_NE_2147822239_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.NE!MTB"
        threat_id = "2147822239"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {07 11 06 02 11 06 91 06 61 11 04 08 91 61 b4 9c 08 03 ?? ?? ?? ?? ?? 17 da fe 01 13 08 11 08 2c 04 16 0c 2b 05 00 08 17 d6 0c 00 11 06 17 d6 13 06 11 06 11 07 13 09 11 09 31 c5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KZ_2147822443_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KZ!MTB"
        threat_id = "2147822443"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 17 16 8d ?? ?? ?? 01 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0d 09 28 ?? ?? ?? 0a 3d 00 6f ?? ?? ?? 0a 74 ?? ?? ?? 1b 28 ?? ?? ?? 0a 0c 08 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AS_2147823785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AS!MTB"
        threat_id = "2147823785"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 07 6f 64 ?? ?? 0a 8e b7 6f 65 ?? ?? 0a 6f 66 ?? ?? 0a 07 08 07 6f 67 ?? ?? 0a 8e b7 6f 65 ?? ?? 0a 6f 68 ?? ?? 0a 73 5a ?? ?? 0a 13 06 11 06 07 6f 69 ?? ?? 0a 17 73 6a ?? ?? 0a 4a 00 72 48 ?? ?? 70 11 05 73 63 ?? ?? 0a 0c 07}  //weight: 3, accuracy: Low
        $x_3_2 = {06 16 28 5b ?? ?? 0a 13 04 08 06 1a 06 8e b7 1a 59 6f 5c ?? ?? 0a 11 04 17 59 17 58 8d 3d ?? ?? 01 0d 08 16 6a}  //weight: 3, accuracy: Low
        $x_1_3 = "StrReverse" ascii //weight: 1
        $x_1_4 = "GZipStream" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "ToArray" ascii //weight: 1
        $x_1_7 = "get_Assembly" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ABH_2147824763_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ABH!MTB"
        threat_id = "2147824763"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {08 1b 62 08 58 11 04 61 0c 11 05 18 58 49 13 04 11 04 39 1d ?? ?? 00 09 1b 62 09 58 11 04 61 0d 11 05 18 d3 18 5a 58 13 05}  //weight: 3, accuracy: Low
        $x_1_2 = "chromeKey" ascii //weight: 1
        $x_1_3 = "EncryptedData" ascii //weight: 1
        $x_1_4 = "GetFiles" ascii //weight: 1
        $x_1_5 = "GetBrowsers" ascii //weight: 1
        $x_1_6 = "GetDefaultIPv4Address" ascii //weight: 1
        $x_1_7 = "AesCryptoServiceProvider" ascii //weight: 1
        $x_1_8 = "Debugger" ascii //weight: 1
        $x_1_9 = "FromBase64String" ascii //weight: 1
        $x_1_10 = "CompressionMode" ascii //weight: 1
        $x_1_11 = "DownloadFile" ascii //weight: 1
        $x_1_12 = "WriteAllBytes" ascii //weight: 1
        $x_1_13 = "GetIPProperties" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ABN_2147827743_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ABN!MTB"
        threat_id = "2147827743"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {03 11 0c 16 11 0a 6f 40 ?? ?? 0a 25 26 26 11 09 11 0c 16 11 0a 11 0b 16 6f 4a ?? ?? 0a 13 0e 7e 0b ?? ?? 04 11 0b 16 11 0e 6f 4b ?? ?? 0a 11 0d 11 0a 58 13 0d}  //weight: 2, accuracy: Low
        $x_2_2 = {14 13 05 de 34 06 07 1f 10 6f 36 ?? ?? 0a 0c 08 20 03 ?? ?? 00 28 39 ?? ?? 0a 25 26 0d 09 28 3a ?? ?? 0a 25 26 13 04 11 04 28 3b ?? ?? 0a 11 04 13 05 de 05}  //weight: 2, accuracy: Low
        $x_1_3 = "Decrypt" ascii //weight: 1
        $x_1_4 = "CryptoStreamMode" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
        $x_1_6 = "FlushFinalBlock" ascii //weight: 1
        $x_1_7 = "FromBase64String" ascii //weight: 1
        $x_1_8 = "Reverse" ascii //weight: 1
        $x_1_9 = "TransformFinalBlock" ascii //weight: 1
        $x_1_10 = "CreateDelegate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ABM_2147829256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ABM!MTB"
        threat_id = "2147829256"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {57 95 a2 3d 09 07 00 00 00 00 00 00 00 00 00 00 02 00 00 00 9b 00 00 00 18 00 00 00 70 00 00 00 34 01 00 00 86 01 00 00}  //weight: 3, accuracy: High
        $x_1_2 = "s919tOWv8W" ascii //weight: 1
        $x_1_3 = "FlushFinalBlock" ascii //weight: 1
        $x_1_4 = "CreateDecryptor" ascii //weight: 1
        $x_1_5 = "Ek4bTwHBLp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ABT_2147830421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ABT!MTB"
        threat_id = "2147830421"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 02 6f 24 ?? ?? 0a 0a de 0a 07 2c 06 07 6f ?? ?? ?? 0a dc 03 72 ?? ?? ?? 70 04 28 ?? ?? ?? 0a 06 28 ?? ?? ?? 0a 20 ?? ?? ?? 00 28 ?? ?? ?? 0a 03 72 ?? ?? ?? 70 04 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 26 de 13}  //weight: 5, accuracy: Low
        $x_1_2 = "get_CurrentDirectory" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "RuWLpKuxDhfA" ascii //weight: 1
        $x_1_5 = "WAOXRKFiVqVT" ascii //weight: 1
        $x_1_6 = "/C choice /C Y /N /D Y /T 3 & Del" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_PSYA_2147831352_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.PSYA!MTB"
        threat_id = "2147831352"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {04 1f 40 8d 62 00 00 01 25 d0 46 00 00 04 28 ?? ?? ?? 0a 80 39 00 00 04 16 80 30 00 00 04 16 80 26 00 00 04 16 8d 64 00 00 01 80 2f 00 00 04 16 8d 64 00 00 01 80 3c 00 00 04 16 8d 64 00 00 01 80 3b 00 00 04 16 8d 64}  //weight: 1, accuracy: Low
        $x_1_2 = {06 11 0f 18 64 e0 07 11 0e 11 0f 19 58 58 e0 91 1f 18 62 07 11 0e 11 0f 18 58 58 ?? ?? ?? 10 62 60 07 11 0e 11 0f 17 58 58 e0 91 1e 62 60 07 11 0e 11 0f 58 e0 91 60 9e 11 0f 1a 58 13 0f 11 0f 1f 3d 44 b9 ff ff ff}  //weight: 1, accuracy: Low
        $x_1_3 = {49 14 16 9a 26 16 2d f9 20 77 00 00 01 28 ?? ?? ?? 06 28 ?? ?? ?? 0a 72 da 01 00 70 18 8d 25 00 00 01 0a 06 16 20 34 00 00 01 28 ?? ?? ?? 06 28 ?? ?? ?? 0a a2 06 17 20 25 00 00 01 28 ?? ?? ?? 06 28 ?? ?? ?? 0a a2 06 28 ?? ?? ?? 0a 14 18 8d 15 00 00 01 0b 07 16 02 8c 34 00 00 01 a2 07 17 03 a2 07 6f b4 00 00 0a 74 5e 00 00 01 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_2147831353_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.psyB!MTB"
        threat_id = "2147831353"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "psyB: an internal category used to refer to some threats"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 14 16 9a 26 16 2d f9 14 0a 28 03 01 00 06 39 2b 00 00 00 72 03 00 00 70 72 a2 00 00 70 28 9e}  //weight: 1, accuracy: High
        $x_1_2 = {04 0a 16 6a 0b 28 aa 00 00 0a 1a 40 14 00 00 00 06 28 aa 00 00 0a 18 5a 28 ab 00 00 0a 6a 0b 38 0e 00 00 00 06 28 aa 00 00 0a 18 5a 28 ac 00 00 0a 0b 7e 28 00 00 04 07 8c 61 00 00 01 6f ad 00 00 0a 0c 08 39 c4 00 00 00 08 a5 16 00 00 02 0d}  //weight: 1, accuracy: High
        $x_1_3 = {14 16 9a 26 16 2d f9 fe 09 00 00 6f ?? ?? ?? 0a 2a}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ABCH_2147835238_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ABCH!MTB"
        threat_id = "2147835238"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 06 07 6f ?? ?? ?? 0a 0d 00 02 09 28 ?? ?? ?? 06 13 04 de 16 09 2c 07 09 6f ?? ?? ?? 0a 00 dc}  //weight: 2, accuracy: Low
        $x_1_2 = {0a 0d 07 09 6f ?? ?? ?? 0a 00 08 6f ?? ?? ?? 0a 2d e9 17 00 08 6f}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateDecryptor" ascii //weight: 1
        $x_1_4 = "WindowsFormsApp21.Properties.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_B_2147835962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.B!MTB"
        threat_id = "2147835962"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "m.htm" wide //weight: 2
        $x_2_2 = "justnothingleaveit" wide //weight: 2
        $x_2_3 = "ConfuserEx" ascii //weight: 2
        $x_2_4 = "Windows Explorer" wide //weight: 2
        $x_2_5 = "87b43f01-0b5e-49b6-8de4-7563e84fd71e" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SPL_2147838629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SPL!MTB"
        threat_id = "2147838629"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {06 16 fe 02 06 19 fe 04 5f 0b 07 2c 08 17 28 ?? ?? ?? 0a 00 00 00 06 1a fe 01 0c 08 2c 08 28 ?? ?? ?? 06 00 2b 09 00 06 17 d6 0a 06 1b 31 d1}  //weight: 3, accuracy: Low
        $x_1_2 = "4System.Web.Services.Protocols.SoapHttpClientProtocol" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SP_2147841201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SP!MTB"
        threat_id = "2147841201"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {20 00 01 00 00 0a 7e 05 00 00 04 28 ?? ?? ?? 0a 0b 07 28 ?? ?? ?? 0a 28 ?? ?? ?? 06 6f ?? ?? ?? 0a 28 ?? ?? ?? 06 06 14 14 7e 09 00 00 04 74 01 00 00 1b 6f ?? ?? ?? 0a 26 17 28 ?? ?? ?? 0a 7e 03 00 00 04 2d ba}  //weight: 4, accuracy: Low
        $x_1_2 = "getdecryptit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SP_2147841201_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SP!MTB"
        threat_id = "2147841201"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "4ea6cc6d-063e-43cf-96ce-b3ec1b707bc5" ascii //weight: 2
        $x_2_2 = "asdjJ.My.Resources" ascii //weight: 2
        $x_2_3 = "EbVk9dMWvodsu0FgZR.NmURtsZH4NPNGZPSBg" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_GFF_2147841689_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.GFF!MTB"
        threat_id = "2147841689"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 05 11 07 02 11 07 91 11 04 11 04 07 94 11 04 08 94 58 20 ff 00 00 00 5f 94 61 28 ?? ?? ?? 0a 9c 00 11 07 17 58 13 07}  //weight: 10, accuracy: Low
        $x_1_2 = "FromBase64String" ascii //weight: 1
        $x_1_3 = "GetCurrentProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_FAS_2147846119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.FAS!MTB"
        threat_id = "2147846119"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {61 07 06 91 61 b4 9c 06 03 6f ?? 00 00 0a 17 da 33 04 16 0a 2b 04 06 17 d6 0a 11 05 17 d6 13 05 11 05 11 06 31}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_GAL_2147847716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.GAL!MTB"
        threat_id = "2147847716"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0b 07 06 6f ?? 00 00 0a 16 73 ?? 00 00 0a 0c 02 8e b7 17 d6 8d ?? 00 00 01 0d 08 09 16 02 8e b7 6f ?? 00 00 0a 13 04 11 04 17 d6 8d ?? 00 00 01 13 05 09 11 05 11 04 28 ?? 00 00 0a 08 6f ?? 00 00 0a de 10}  //weight: 3, accuracy: Low
        $x_2_2 = "0HUsf2KxcgStEihGe62ViTM62mLe1Exb0he9NWbXeD3lAw" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MAAW_2147848742_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MAAW!MTB"
        threat_id = "2147848742"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$71FED0CE-2192-4568-A8CF-7DE361021ECF" ascii //weight: 1
        $x_1_2 = "$dee576ac-16b3-4057-a2bb-efc7fc2dae0c" ascii //weight: 1
        $x_1_3 = "$fdf15c5e-36dd-4455-8600-6a7e93e08c34" ascii //weight: 1
        $x_1_4 = "$4115afc4-a174-4bdc-acaf-cc19ca4e3e50" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MBEG_2147849061_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MBEG!MTB"
        threat_id = "2147849061"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 00 41 00 41 00 41 00 41 00 77 00 67 00 41 00 41 00 72 00 48 00 67 00 41 00 52 00 68 00 77 00 48 00 77 00 74 00 42 00 33 00 6e 00 41 00 51 00 77 00 51 00 41 00 41 00 49 00 41 00 69 00 6d 00 77}  //weight: 1, accuracy: High
        $x_1_2 = {66 00 42 00 43 00 63 00 43 00 4b 00 42 00 42 00 41 00 46 00 47 00 41 00 41 00 4b 00 45 00 42 00 6a 00 4b 00 41 00 43 00 41 00 41 00 51 00 63 00 45 00 62 00 41 00 41 00 46 00 43 00 41 00 41 00 78 00 4b 00 4b 00 46 00 42 00 68 00 41 00 41 00 41}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ARAC_2147849370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ARAC!MTB"
        threat_id = "2147849370"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 1f 0a 38 ?? ?? ?? ?? 17 11 08 58 13 08 11 08 08 fe 04}  //weight: 2, accuracy: Low
        $x_2_2 = "5s8s8Qv" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ARAC_2147849370_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ARAC!MTB"
        threat_id = "2147849370"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 05 11 06 91 13 07 08 17 58 20 ff 00 00 00 5f 0c 09 06 08 91 58 20 ff 00 00 00 5f 0d 06 08 09 28 0a 00 00 06 07 11 04 11 07 06 06 08 91 06 09 91 58 20 ff 00 00 00 5f 91 61 d2 9c 11 06 17 58 13 06 11 06 11 05 8e 69 32 b6}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KU_2147849821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KU!MTB"
        threat_id = "2147849821"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 00 01 14 14 14 28 ?? 00 00 06 14 20}  //weight: 2, accuracy: Low
        $x_2_2 = {00 00 01 13 16 11 16 16 14 a2}  //weight: 2, accuracy: High
        $x_2_3 = {00 11 16 17 14 a2}  //weight: 2, accuracy: High
        $x_2_4 = {00 11 16 14 14 14 28}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ASCB_2147851990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ASCB!MTB"
        threat_id = "2147851990"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {09 06 08 59 61 d2 13 04 09 1e 63 08 61 d2 13 05 38 ?? 00 00 00 0d 38 ?? 00 00 00 07 08 11 05 1e 62 11 04 60 d1 9d 38 ?? 00 00 00 0b 38 ?? 00 00 00 08 17 58 0c 38 ?? 00 00 00 0a 38 ?? 00 00 00 08 07 8e 69 38 ?? 00 00 00 28 ?? 00 00 0a 2a}  //weight: 4, accuracy: Low
        $x_1_2 = {11 05 11 08 09 06 11 08 58 93 11 06 11 08 07 58 11 07 5d 93 61 d1 9d 38}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SL_2147852031_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SL!MTB"
        threat_id = "2147852031"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {08 07 11 18 9a 1f 10 7e 9b 02 00 04 28 ?? ?? ?? 06 86 6f ?? ?? ?? 0a 11 18 17 d6 13 18 11 18 11 17 3e da ff ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAC_2147852436_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAC!MTB"
        threat_id = "2147852436"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {07 08 17 d6 02 07 08 91 03 08 91 6f ?? 00 00 06 9c 00 08 17 d6 0c 08 09 13 04 11 04 31 e2}  //weight: 10, accuracy: Low
        $x_1_2 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" wide //weight: 1
        $x_1_3 = "HACKER" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ASCC_2147890337_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ASCC!MTB"
        threat_id = "2147890337"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DBRBHPeKlGIRYgagWVm" ascii //weight: 1
        $x_1_2 = "XuAO3le4C6WjP9tMxIH" ascii //weight: 1
        $x_1_3 = "ts92MseMbweepQv931y" ascii //weight: 1
        $x_1_4 = "OAXd7IcwUB195yNbsVK" ascii //weight: 1
        $x_1_5 = "ynIhCMu4HrAG77oJu0c" ascii //weight: 1
        $x_1_6 = "VW7ivjgKvODqQmRqrcm" ascii //weight: 1
        $x_1_7 = "xra8xOYACcZLOEIdG1.7QPJAtJLH9hkO4Nex9" ascii //weight: 1
        $x_1_8 = "$fb9dff60-6e73-413c-8cb9-15e101d74773" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SN_2147891912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SN!MTB"
        threat_id = "2147891912"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "33333333.g.resources" ascii //weight: 1
        $x_1_2 = "aR3nbf8dQp2feLmk31.lSfgApatkdxsVcGcrktoFd.resources" ascii //weight: 1
        $x_1_3 = "{11111-22222-40001-00001}" ascii //weight: 1
        $x_1_4 = "33333333.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_NBM_2147892304_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.NBM!MTB"
        threat_id = "2147892304"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {28 1e 00 00 0a a2 28 ?? 00 00 0a 0d 09 28 ?? 00 00 0a 07 6f ?? 00 00 0a 18 14 28 ?? 00 00 0a 13 04 11 04 28 ?? 00 00 0a 08 6f 1d 00 00 0a 17}  //weight: 5, accuracy: Low
        $x_1_2 = "WindowsFormsApp1.Properties.Resources.resources" ascii //weight: 1
        $x_1_3 = "exe2powershell-master" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MBJS_2147892594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MBJS!MTB"
        threat_id = "2147892594"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0a 13 04 11 04 09 16 09 8e b7 6f ?? 00 00 0a 26 11 05}  //weight: 1, accuracy: Low
        $x_1_2 = "EGZc1ID5X0XoCXqhnQXW2wmvXWF9MVrAYCUL" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MBKL_2147894059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MBKL!MTB"
        threat_id = "2147894059"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {16 0d 06 09 28 ?? 00 00 0a 22 00 00 20 41 5a 22 00 00 82 42 58 28 ?? 00 00 0a 6c 28 ?? 00 00 0a b7 28 ?? 00 00 0a 9d 02 6f ?? 00 00 06 13 06 11 06 11 06 6f ?? 00 00 0a 06 09 93}  //weight: 1, accuracy: Low
        $x_1_2 = "6754614002fe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MBKS_2147894651_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MBKS!MTB"
        threat_id = "2147894651"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {0a 0b 08 6f ?? 00 00 0a 00 73 ?? 00 00 0a 0d 09 07 6f ?? 00 00 0a 00 09 04 6f ?? 00 00 0a 00 09 05 6f ?? 00 00 0a 00 09 6f ?? 00 00 0a 13 04 11 04 02 16 02 8e 69 6f}  //weight: 10, accuracy: Low
        $x_1_2 = "05e4a4c6-dbc2-4ca8-b3db-462cd5a83f82" ascii //weight: 1
        $x_1_3 = "imfree2.Resources.resource" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AAVR_2147895536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AAVR!MTB"
        threat_id = "2147895536"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {07 20 f9 00 00 00 20 af 00 00 00 28 29 00 00 06 02 16 02 8e b7 6f ?? 00 00 0a 0a de 6e de 45}  //weight: 4, accuracy: Low
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AAVT_2147895554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AAVT!MTB"
        threat_id = "2147895554"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 13 05 16 13 04 2b 29 11 05 11 04 9a 0d 08 72 ?? ?? 00 70 09 28 ?? 01 00 0a 28 ?? 01 00 0a 28 ?? 01 00 0a 6f ?? 01 00 0a 26 11 04 17 d6 13 04 00 11 04 11 05 8e b7 fe 04 13 06 11 06 2d c9}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KA_2147896226_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KA!MTB"
        threat_id = "2147896226"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {11 0e 91 61 b4 9c 11 0e 03 6f ?? 00 00 0a 17 da 33 05 16 13 0e 2b 06 11 0e 17 d6}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAI_2147896284_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAI!MTB"
        threat_id = "2147896284"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 11 08 8f ?? 00 00 01 25 71 ?? 00 00 01 11 0e 06 5a 11 06 58 20 07 88 d4 e0 20 f9 78 2b 1f 58 5e d2 61 d2 81 ?? 00 00 01 11 0e 06 5a 11 05 58 20 f0 1e e0 04 20 fc fe 4c 5f 58 20 ec 1d 2c 64 59 5e d1 0a 11 0e 11 06 5a 11 0c 58 20 9f 2f f5 d1 20 61 d0 0b 2e 58 5e d1 13 06 11 08 17 58 13 08 11 08 11 04 8e 69 fe 04 2d 94}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_GCE_2147896363_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.GCE!MTB"
        threat_id = "2147896363"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RW5jcnlwdGFkbyQ=" ascii //weight: 1
        $x_1_2 = "cc817d62a421aff1643bdc60e1353cbb2" ascii //weight: 1
        $x_1_3 = "FromBase64String" ascii //weight: 1
        $x_1_4 = "Encryptado.exe" ascii //weight: 1
        $x_1_5 = "CreateDecryptor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAK_2147896407_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAK!MTB"
        threat_id = "2147896407"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {07 16 9a 7e ?? 00 00 04 28 ?? 00 00 0a 6f ?? 00 00 0a 13 22 11 21 06 11 22 06 8e 69 11 22 59 6f ?? 00 00 0a 11 21}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAL_2147896424_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAL!MTB"
        threat_id = "2147896424"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {09 11 04 16 6f ?? 00 00 0a 13 08 12 08 28 ?? 00 00 0a 6f ?? 00 00 0a 11 04 17 d6 13 04 11 04 11 07 31 d8}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ABQ_2147896631_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ABQ!MTB"
        threat_id = "2147896631"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {06 07 6f 27 ?? ?? 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f ?? ?? ?? 0a 08 6f ?? ?? ?? 0a 06 6f ?? ?? ?? 0a 0d 09 2a}  //weight: 5, accuracy: Low
        $x_1_2 = "GZipStream" ascii //weight: 1
        $x_1_3 = "DownloadData" ascii //weight: 1
        $x_1_4 = "e09uAvZ6Q" ascii //weight: 1
        $x_1_5 = "HttpResponse" ascii //weight: 1
        $x_1_6 = "FlushFinalBlock" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ABU_2147896632_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ABU!MTB"
        threat_id = "2147896632"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {57 15 a2 1d 09 0d 00 00 00 fa 01 33 00 16 00 00 01 00 00 00 50 00 00 00 1e 00 00 00 1b 00 00 00 1c 02 00 00 66 00 00 00}  //weight: 5, accuracy: High
        $x_1_2 = "CreateDecryptor" ascii //weight: 1
        $x_1_3 = "DeflateStream" ascii //weight: 1
        $x_1_4 = "get_CurrentDomain" ascii //weight: 1
        $x_1_5 = "TransformFinalBlock" ascii //weight: 1
        $x_1_6 = "IsDebuggerPresent" ascii //weight: 1
        $x_1_7 = "get_IsAttached" ascii //weight: 1
        $x_1_8 = "IsLogging" ascii //weight: 1
        $x_1_9 = "Confuser" ascii //weight: 1
        $x_1_10 = "Debugger detected" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AAWQ_2147896796_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AAWQ!MTB"
        threat_id = "2147896796"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {11 04 13 05 09 13 06 11 05 11 06 30 37 02 11 04 28 ?? 00 00 0a 03 11 04 03 6f ?? 00 00 0a 5d 07 d6 28 ?? 00 00 0a da 13 07 06 11 07 28 ?? 00 00 0a 28 ?? 00 00 0a 28 ?? 00 00 0a 0a 11 04 17 d6 13 04 2b bc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAO_2147900004_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAO!MTB"
        threat_id = "2147900004"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {09 11 06 03 11 06 91 08 61 07 11 04 91 61 b4 9c}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAP_2147901161_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAP!MTB"
        threat_id = "2147901161"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {10 01 03 28 ?? 00 00 0a 18 5b 17 da 17 d6 8d ?? 00 00 01 0c 07 16 8c ?? 00 00 01 08 17 28 ?? 00 00 0a 18 da}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_BPAA_2147901176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.BPAA!MTB"
        threat_id = "2147901176"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {72 1f 00 00 70 80 ?? 00 00 04 7e ?? 00 00 04 28 ?? 00 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 80 ?? 00 00 04 2a}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAR_2147901607_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAR!MTB"
        threat_id = "2147901607"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {58 4a 91 08 08 06 4b 84 95 08 06 1a 58 4b 84 95 d7 6e 20 ?? 00 00 00 6a 5f b7 95 61 86 9c 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AMBB_2147902313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AMBB!MTB"
        threat_id = "2147902313"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {11 16 d2 13 2c 11 16 1e 63 d1 13 16 11 1e 11 09 91 13 26 11 1e 11 09 11 26 11 24 61 11 1b 19 58 61 11 2c 61 d2 9c 11 09 17 58 13 09 11 26 13 1b}  //weight: 2, accuracy: High
        $x_1_2 = "Reverse" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_EBAA_2147902730_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.EBAA!MTB"
        threat_id = "2147902730"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 83 00 00 04 28 ?? 01 00 06 28 ?? 01 00 06 28 ?? 00 00 0a 28 ?? 00 00 0a 80 ?? 00 00 04 20 07 00 00 00 38 ?? fe ff ff 72 b6 02 00 70 80 ?? 00 00 04 20 01 00 00 00 fe 0e 00 00 38 ?? fe ff ff 72 b6 02 00 70 80 ?? 00 00 04 20 05 00 00 00 fe 0e 00 00 16 39 ?? fe ff ff 00 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_EKAA_2147902910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.EKAA!MTB"
        threat_id = "2147902910"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 06 8e b7 1f 11 da 17 d6 8d ?? 00 00 01 13 04 06 1f 10 11 04 16 06 8e b7 1f 10 da 28 ?? 00 00 0a 00 11 04 0c 2b 00 08 2a}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AMBE_2147902976_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AMBE!MTB"
        threat_id = "2147902976"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {07 11 09 11 08 5d 17 6f ?? 00 00 0a 6f ?? 00 00 0a 16 93}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AMBE_2147902976_1
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.AMBE!MTB"
        threat_id = "2147902976"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {13 05 11 05 16 11 04 16 1e 28 ?? 00 00 0a 00 07 11 04 6f ?? 00 00 0a 00 07 18 6f ?? 00 00 0a 00 07 6f ?? 00 00 0a 13 06 02 28 ?? 00 00 0a 13 07 28 ?? 00 00 0a 11 06 11 07 16 11 07 8e 69 6f ?? 00 00 0a 6f ?? 00 00 0a 0d 09 0a de 11}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_EPAA_2147903005_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.EPAA!MTB"
        threat_id = "2147903005"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 18 2b a7 06 28 ?? 00 00 0a 72 f0 0a 01 70 1e 28 ?? 00 00 06 18 19 28 ?? 00 00 06 0b 19 2b 8b 28 ?? 00 00 0a 07 6f ?? 00 00 0a 0c}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_EUAA_2147903182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.EUAA!MTB"
        threat_id = "2147903182"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {0a 11 06 28 ?? 00 00 0a 6f ?? 00 00 0a 0b 07 14 72 e1 3c 00 70 16 8d ?? 00 00 01 14 14 14 28 ?? 00 00 0a 14 72 f7 3c 00 70 18 8d ?? 00 00 01 13 57 11 57 16 14 a2}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAW_2147904786_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAW!MTB"
        threat_id = "2147904786"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5d b4 03 07 03 8e b7 6a 5d b7 91 61 9c 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAU_2147905520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAU!MTB"
        threat_id = "2147905520"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b7 07 11 0b 18 6f ?? 00 00 0a 1f 10 28 ?? 00 00 0a 9c 11 0b 18 d6 13 0b 11 0b 11 0a 31 cf}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_MBZW_2147907075_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.MBZW!MTB"
        threat_id = "2147907075"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6d 65 6b 61 6c 69 62 65 70 6f 6a 79 68 65 00 71 61 70 69 66 65 78 75 67 61 72 6f 6c 75 72 75 6a 65 00 45 6e 64 49}  //weight: 1, accuracy: High
        $x_1_2 = "GZipStream" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAV_2147910954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAV!MTB"
        threat_id = "2147910954"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {09 06 16 11 04 6f ?? 00 00 0a 00 07 06 16 06 8e b7 6f ?? 00 00 0a 13 04 00 11 04 16 fe 02 13 06 11 06 2d dc}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAY_2147911017_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAY!MTB"
        threat_id = "2147911017"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {84 95 d7 6e 20 ff 00 00 00 6a 5f b7 95 61 86 9c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAZ_2147917509_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAZ!MTB"
        threat_id = "2147917509"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 06 02 06 91 11 04 61 09 07 91 61 b4 9c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_KAAB_2147920822_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.KAAB!MTB"
        threat_id = "2147920822"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 61 d2 61 d2 81 ?? 00 00 01 11 07 17 58 13 07 1e 13 09}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SQ_2147923795_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SQ!MTB"
        threat_id = "2147923795"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 11 05 02 11 05 91 06 61 09 08 91 61 b4 9c 08 03 6f 37 00 00 0a 17 da fe 01 13 07 11 07 2c 04}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SS_2147924847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SS!MTB"
        threat_id = "2147924847"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {02 07 16 28 0e 00 00 06 0c 12 02 28 47 00 00 0a 0d 12 02 28 48 00 00 0a 13 04 12 02 28 49 00 00 0a 13 05 06 09}  //weight: 2, accuracy: High
        $x_2_2 = "X.lugia.resources" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ST_2147924848_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ST!MTB"
        threat_id = "2147924848"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {06 07 8f 1e 00 00 01 25 71 1e 00 00 01 02 07 1f 10 5d 91 61 d2 81 1e 00 00 01 07 17 58 0b 07 06 8e 69}  //weight: 2, accuracy: High
        $x_2_2 = "MyImgur Programming Team" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ARAZ_2147928301_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ARAZ!MTB"
        threat_id = "2147928301"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "UGF5bG9hZC5leGU=" wide //weight: 2
        $x_2_2 = "bmV0c2ggZmlyZXdhbGwgZGVsZXRlIGFsbG93ZWRwcm9ncmFtICI=" wide //weight: 2
        $x_2_3 = "Y21kLmV4ZSAvYyBwaW5nIDAgLW4gMiAmIGRlbCAi" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_ABJA_2147931099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.ABJA!MTB"
        threat_id = "2147931099"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {06 1a 58 4a 02 8e 69 5d 1f 67 59 1f 67 58 02 06 1a 58 4a 02 8e 69 5d 1e 58 1f 15 58 1f 1d 59 91 07 06 1a 58 4a 07 8e 69 5d 1d 58 1f 0d 58 1f 15 59 1f 17 58 1f 16 59 91 61 02 06 1a 58 4a 20 0b 02 00 00 58 20 0a 02 00 00 59 1f 09 59 1f 09 58 02 8e 69 5d 1f 09 58 1f 0e 58 1f 17 59 91 59 20 fa 00 00 00 58 1c 58 20 00 01 00 00 5d d2 9c 06 1a 58 06 1a 58 4a 17 58 54}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_AMTB_2147945336_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi!AMTB"
        threat_id = "2147945336"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "key_logger_Load" ascii //weight: 1
        $x_1_2 = "SpyNote_Activated" ascii //weight: 1
        $x_1_3 = "PayloadToolStripMenuItem_Click" ascii //weight: 1
        $x_1_4 = "LogsSpyNote" ascii //weight: 1
        $n_100_5 = "Uninst.exe" ascii //weight: -100
        $n_100_6 = "Uninstaller.exe" ascii //weight: -100
        $n_100_7 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Backdoor_MSIL_Bladabindi_SV_2147947655_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Bladabindi.SV!MTB"
        threat_id = "2147947655"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Bladabindi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {07 09 08 09 1e d8 1e 6f 26 00 00 0a 18 28 27 00 00 0a 9c 09 17 d6 0d 09 11 04 13 05 11 05 31 e0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

