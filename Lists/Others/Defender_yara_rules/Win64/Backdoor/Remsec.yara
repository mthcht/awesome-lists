rule Backdoor_Win64_Remsec_G_2147716726_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Remsec.G!dha"
        threat_id = "2147716726"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Remsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {56 55 8b ec be ?? ?? ?? ?? 50 ad 8b c8 ad ff e1 c9 5e ff e0 ff 20 8b f0 eb ef 8f 00 8b 00 eb}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Remsec_A_2147716735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Remsec.A!dha"
        threat_id = "2147716735"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Remsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {2f ce 79 27}  //weight: 10, accuracy: High
        $x_10_2 = {7b 30 ff ff}  //weight: 10, accuracy: High
        $x_10_3 = {85 cf 00 00}  //weight: 10, accuracy: High
        $x_10_4 = {cd 2b 00 00}  //weight: 10, accuracy: High
        $x_10_5 = "PasswordChangeNotify" ascii //weight: 10
        $x_10_6 = "InitializeChangeNotify" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Remsec_C_2147716736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Remsec.C!dha"
        threat_id = "2147716736"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Remsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "InitializePrintProvidor" ascii //weight: 10
        $x_10_2 = {8d 88 00 00 00 3a}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Remsec_D_2147716737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Remsec.D!dha"
        threat_id = "2147716737"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Remsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {b8 7a 7a 7a 7a}  //weight: 10, accuracy: High
        $x_10_2 = {b8 71 71 71 71}  //weight: 10, accuracy: High
        $x_10_3 = {b8 79 79 79 79}  //weight: 10, accuracy: High
        $x_10_4 = {e9 9b f5 c6 ac e9 87 a9 9b bb 87 a3 88}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Remsec_E_2147716738_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Remsec.E!dha"
        threat_id = "2147716738"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Remsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2010"
        strings_accuracy = "High"
    strings:
        $x_1000_1 = {43 00 6f 00 6d 00 70 00 61 00 6e 00 79 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 20 00 43 00 6f 00 72 00 70 00 6f 00 72 00 61 00 74 00 69 00 6f 00 6e 00}  //weight: 1000, accuracy: High
        $x_1000_2 = {50 00 72 00 6f 00 64 00 75 00 63 00 74 00 4e 00 61 00 6d 00 65 00 00 00 00 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 ae 00 20 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 ae 00 20 00 4f 00 70 00 65 00 72 00 61 00 74 00 69 00 6e 00 67 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 1000, accuracy: High
        $x_10_3 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00}  //weight: 10, accuracy: High
        $x_10_4 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00}  //weight: 10, accuracy: High
        $x_10_5 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 10, accuracy: High
        $x_10_6 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 44 00 69 00 73 00 74 00 72 00 69 00 62 00 75 00 74 00 65 00 64 00 20 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 10, accuracy: High
        $x_10_7 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 44 00 69 00 73 00 74 00 72 00 69 00 62 00 75 00 74 00 65 00 64 00 20 00 50 00 72 00 6f 00 74 00 65 00 63 00 74 00 65 00 64 00 20 00 53 00 74 00 6f 00 72 00 61 00 67 00 65 00 20 00 46 00 69 00 6c 00 74 00 65 00 72 00}  //weight: 10, accuracy: High
        $x_10_8 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 44 00 69 00 73 00 74 00 72 00 69 00 62 00 75 00 74 00 65 00 64 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00}  //weight: 10, accuracy: High
        $x_10_9 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 49 00 6e 00 74 00 65 00 72 00 6e 00 65 00 74 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 4d 00 61 00 6e 00 61 00 67 00 65 00 72 00}  //weight: 10, accuracy: High
        $x_10_10 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00}  //weight: 10, accuracy: High
        $x_10_11 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 4c 00 6f 00 63 00 61 00 74 00 6f 00 72 00}  //weight: 10, accuracy: High
        $x_10_12 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 10, accuracy: High
        $x_10_13 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 4e 00 65 00 74 00 77 00 6f 00 72 00 6b 00 20 00 44 00 69 00 73 00 6b 00}  //weight: 10, accuracy: High
        $x_10_14 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 43 00 6c 00 69 00 65 00 6e 00 74 00}  //weight: 10, accuracy: High
        $x_10_15 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 20 00 46 00 69 00 6c 00 74 00 65 00 72 00}  //weight: 10, accuracy: High
        $x_10_16 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 4c 00 6f 00 63 00 61 00 74 00 6f 00 72 00}  //weight: 10, accuracy: High
        $x_10_17 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 43 00 6f 00 6e 00 66 00 69 00 67 00 75 00 72 00 61 00 74 00 69 00 6f 00 6e 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 10, accuracy: High
        $x_10_18 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 46 00 69 00 6c 00 74 00 65 00 72 00}  //weight: 10, accuracy: High
        $x_10_19 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 44 00 69 00 73 00 6b 00 20 00 46 00 69 00 6c 00 74 00 65 00 72 00}  //weight: 10, accuracy: High
        $x_10_20 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 52 00 65 00 6d 00 6f 00 74 00 65 00 20 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 20 00 45 00 6e 00 67 00 69 00 6e 00 65 00}  //weight: 10, accuracy: High
        $x_10_21 = {46 00 69 00 6c 00 65 00 44 00 65 00 73 00 63 00 72 00 69 00 70 00 74 00 69 00 6f 00 6e 00 00 00 00 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 20 00 44 00 65 00 73 00 6b 00 74 00 6f 00 70 00 20 00 53 00 79 00 73 00 74 00 65 00 6d 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1000_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win64_Remsec_I_2147716739_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Remsec.I!dha"
        threat_id = "2147716739"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Remsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "40"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {83 c4 e4 e8 ?? 00 00 00 eb}  //weight: 10, accuracy: Low
        $x_10_2 = {d9 34 24 e8 ?? ?? 00 00 c3}  //weight: 10, accuracy: Low
        $x_10_3 = {83 c4 04 89 e5 e8 ?? 00 00 00 e9}  //weight: 10, accuracy: Low
        $x_10_4 = {83 c4 04 60 e8 ?? 00 00 00 e9}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_Win64_Remsec_J_2147716740_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win64/Remsec.J!dha"
        threat_id = "2147716740"
        type = "Backdoor"
        platform = "Win64: Windows 64-bit platform"
        family = "Remsec"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {6b 67 61 74 65 2e 64 6c 6c 00 69 6e 69 74 32 00 6d 61 69 6e 32 00 76 65 72 73 69 6f 6e 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

