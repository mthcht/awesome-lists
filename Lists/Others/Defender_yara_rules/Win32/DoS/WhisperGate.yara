rule DoS_Win32_WhisperGate_A_2147810460_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/WhisperGate.A!dha"
        threat_id = "2147810460"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 6f 75 72 20 68 61 72 64 20 64 72 69 76 65 20 68 61 73 20 62 ?? 65 6e 20 63 6f 72 72 75 70 74 65 64 2e 0d 0a}  //weight: 1, accuracy: Low
        $x_1_2 = {49 6e 20 63 61 73 65 20 79 6f 75 20 77 61 6e 74 20 74 6f 20 72 65 63 6f 76 ?? 72 20 61 6c 6c 20 68 61 72 64 20 64 72 69 76 65 73 0d 0a 6f 66 20 79 6f 75 72 20 6f 72 67 61 6e 69 7a 61 74 69 6f 6e 2c 0d 0a}  //weight: 1, accuracy: Low
        $x_1_3 = {59 6f 75 20 73 68 6f 75 6c 64 20 70 61 79 20 75 73 20 20 24 31 30 6b 20 76 69 61 20 62 69 ?? 63 6f 69 6e 20 77 61 6c 6c 65 74 0d 0a}  //weight: 1, accuracy: Low
        $x_1_4 = {31 41 56 4e 4d 36 38 67 6a 36 50 47 50 46 63 4a 75 66 ?? 4b 41 54 61 34 57 4c 6e 7a 67 38 66 70 66 76}  //weight: 1, accuracy: Low
        $x_1_5 = {61 6e 64 20 73 65 6e 64 20 6d 65 73 73 61 67 65 20 76 ?? 61 0d 0a 74 6f 78 20 49 44 20}  //weight: 1, accuracy: Low
        $x_1_6 = {38 42 45 44 43 34 31 31 30 31 32 41 33 33 42 41 33 34 46 34 39 ?? 33 30 44 30 46 31 38 36 39 39 33 43 36 41 33 32 44 41 44 38 39 37 36 46 36 41 35 44 38 32 43 31 45 ?? 32 33 30 35 34 43 30 35 37 45 43 45 44 35 34 39 36 46 36 35}  //weight: 1, accuracy: Low
        $x_1_7 = {77 69 74 68 20 79 6f 75 72 20 6f 72 67 61 6e 69 7a 61 ?? 69 6f 6e 20 6e 61 6d 65 2e 0d 0a 57 65 20 77 69 6c 6c 20 63 6f 6e 74 61 63 74 20 79 6f 75 20 74 6f 20 ?? 69 76 65 20 66 75 72 74 68 65 72 20 69 6e 73 74 72 75 63 74 69 6f 6e 73 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule DoS_Win32_WhisperGate_C_2147810461_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/WhisperGate.C!dha"
        threat_id = "2147810461"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {eb 00 8c c8 8e d8 be 88 7c e8 00 00 50 fc 8a ?? 3c 00 74 06 e8 05 00 46 eb f4 eb 05 b4 0e cd 10}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 8c c8 8e d8 a3 78 7c 66 c7 06 76 7c 82 7c ?? 00 b4 43 b0 00 8a 16 87 7c 80 c2 80 be 72 7c cd}  //weight: 1, accuracy: Low
        $x_1_3 = {13 72 02 73 18 fe 06 87 7c 66 c7 06 7a 7c 01 00 ?? 00 66 c7 06 7e 7c 00 00 00 00 eb c4 66 81 06}  //weight: 1, accuracy: Low
        $x_1_4 = {7a 7c c7 00 00 00 66 81 16 7e 7c 00 00 00 ?? f8 eb af 10 00 01 00 00 00 00 00 01 00 00 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule DoS_Win32_WhisperGate_M_2147810985_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/WhisperGate.M"
        threat_id = "2147810985"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "WhisperGate"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "cmd.exe /min /C ping 111.111.111.111" ascii //weight: 2
        $x_2_2 = {25 00 2e 00 2a 00 73 00 2e 00 25 00 78 00 00 00 77 00 62 00}  //weight: 2, accuracy: High
        $x_2_3 = {89 c2 b9 00 00 10 00 b0 cc 89 d7 89 55 e0 f3 aa}  //weight: 2, accuracy: High
        $x_1_4 = {2e 00 56 00 42 00 53 00 00 00 2e 00 50 00 53 00 31 00 00 00 2e 00 42 00 41 00 54 00 00 00 2e 00 43 00 4d 00 44 00}  //weight: 1, accuracy: High
        $x_1_5 = {2e 00 48 00 54 00 4d 00 4c 00 00 00 2e 00 48 00 54 00 4d 00 00 00 2e 00 53 00 48 00 54 00 4d 00 4c 00 00 00 2e 00 58 00 48 00 54 00 4d 00 4c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

