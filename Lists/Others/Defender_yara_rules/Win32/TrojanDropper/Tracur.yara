rule TrojanDropper_Win32_Tracur_B_2147678586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tracur.gen!B"
        threat_id = "2147678586"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Nullsoft Install System" ascii //weight: 1
        $x_1_2 = {fd 8d 80 00 43 4c 53 49 44 5c 7b 44 32 37 43 44 42 36 45 2d 41 45 36 44 2d 31 31 63 66}  //weight: 1, accuracy: High
        $x_1_3 = {00 24 7b 73 79 73 47 65 74 4c 6f 67 69 63 61 6c 44 72 69 76 65 53 74 72 69 6e 67 73 7d 28 31 30 32 34 2c 20 72 31 29}  //weight: 1, accuracy: High
        $x_1_4 = {00 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 22 fd}  //weight: 1, accuracy: High
        $x_1_5 = {6d 79 4d 75 74 65 78 22 29 20 69 20 2e 72 31 20 3f 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Tracur_D_2147682243_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tracur.gen!D"
        threat_id = "2147682243"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5e 8b 5d 08 56 be ?? (10|30|60) 00 00 bb ?? ?? ?? ?? 03 75 08 b9 (96|ff|8e|cf|99|95|8f) 00 00 00 01 d8 01 5e 04 01 1e 83 c6 08 31 1e 83 c6 04 [0-2] 66 31 1e [0-2] 83 c6 02 30 1e 83 c6 01 e2 ?? [0-1] eb}  //weight: 1, accuracy: Low
        $x_1_2 = {5e 8b 5d 08 56 be ?? (10|30|60) 00 00 bb ?? ?? ?? ?? 03 75 08 b9 (96|ff|8e|cf|99|95|8f|fe) 00 00 00 01 d8 01 5e 04 01 1e 83 c6 08 31 1e 83 c6 04 [0-2] 66 31 1e [0-2] 83 c6 02 30 1e 83 c6 01 49 75}  //weight: 1, accuracy: Low
        $x_1_3 = {5e 8b 5d 08 56 be ?? 10 00 00 bb ?? ?? ?? ?? 03 75 08 b9 ?? 00 00 00 01 d8 01 1e 01 5e 04 83 c6 08 31 1e 83 c6 04 66 31 1e 41 83 c6 02 30 1e 83 c6 01 49 e2}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 5d 08 56 b9 (fe|fd) 00 00 00 be ?? 10 00 00 bb ?? ?? ?? ?? 03 75 08 [0-4] 01 d8 01 1e 01 5e 04 83 c6 08 31 1e 83 c6 04 66 31 1e [0-4] 83 c6 02 30 1e 83 c6 01 [0-4] (e2|49 75)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Tracur_G_2147682307_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tracur.gen!G"
        threat_id = "2147682307"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {75 06 83 7d 00 00 74 79 55 89 e5 80 7d 0c 01 75 22 ba ?? ?? ?? ?? 56 52 b9 ?? ?? ?? ?? be 8e ?? 00 00 03 75 08 81 f1 ?? ?? ?? ?? d3 ca 30 36 ac e2 f9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Tracur_E_2147682308_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tracur.gen!E"
        threat_id = "2147682308"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 7d 08 b9 ?? ?? 00 00 31 c8 d3 0f (28|29) 07 d3 0f 83 ef 04 e2 f3 0a 00 bf ?? (1b|3b) 00 00 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {03 7d 08 b9 ?? ?? 00 00 31 c8 d3 0f 28 07 d3 0f 83 ef 04 49 75 f2 0a 00 bf ?? 1b 00 00 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Tracur_F_2147682309_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tracur.gen!F"
        threat_id = "2147682309"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {03 7d 08 b9 03 02 02 02 ce 03 d5 02 d2 02 00 00 31 c8 d3 0f (29|28) 07 d3 0f 83 ef 04 49 74 ?? eb f0 16 00 bf ?? (1f|1c|1b) 00 00 b8}  //weight: 1, accuracy: Low
        $x_1_2 = {03 7d 08 b9 (ce 03|d5 02) 00 00 31 c8 d3 0f (29|28) 07 d3 0f 83 ef 04 e2 f3 eb 16 00 bf ?? 1f 00 00 b8}  //weight: 1, accuracy: Low
        $x_1_3 = {03 7d 08 31 c8 d3 0f 29 07 d3 0f 83 ef 04 49 75 11 00 b9 ce 03 00 00 56 b8 ?? ?? ?? ?? 53 bf ?? 1f 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {03 7d 08 31 c8 d3 0f 29 07 d3 0f 83 ef 04 ?? ?? 49 75 11 00 b9 ce 03 00 00 56 b8 ?? ?? ?? ?? 53 bf ?? 1f 00 00}  //weight: 1, accuracy: Low
        $x_1_5 = {03 7d 08 b9 ce 02 00 00 31 c8 d3 0f (28|29) 07 d3 0f 83 ef 04 49 (74|75) ?? eb f0 0a 00 bf ?? ?? 00 00 b8}  //weight: 1, accuracy: Low
        $x_1_6 = {03 7d 08 b9 ce 03 00 00 31 c8 d3 0f (29|28) 07 d3 0f 83 ef 04 49 75 f2 eb 0a 00 bf ?? ?? 00 00 b8}  //weight: 1, accuracy: Low
        $x_1_7 = {03 7d 08 b9 a5 02 00 00 31 c8 d3 0f d3 0f 28 07 83 ef 04 e2 f3 0a 00 bf ?? 1b 00 00 b8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Tracur_H_2147682327_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tracur.gen!H"
        threat_id = "2147682327"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7d 0c 01 75 27 ba ?? ?? ?? ?? 56 52 b9 ?? ?? ?? ?? 31 d1 be ?? 90 00 00 81 f1 ?? ?? ?? ?? 03 75 08 d3 ca 83 fa 00 30 36 ac e2 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Tracur_I_2147682381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tracur.gen!I"
        threat_id = "2147682381"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 d4 29 e0 75 07 8b 4d 00 85 c9 74 (25|23) 55 89 e5 80 7d 0c 01 75 (24|22) ba ?? ?? ?? ?? 56 52 b9 ?? ?? ?? ?? 31 d1 be ?? (20|10) 00 00 03 75 08 81 f1 ?? ?? ?? ?? d3 ca 30 36 ac e2 f9}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 45 d4 29 ?? 75 (08|07) 8b 4d 00 [0-1] 85 c9 74 25 55 89 e5 80 7d 0c 01 75 ?? ba ?? ?? ?? ?? 56 52 b9 ?? ?? ?? ?? 31 d1 be ?? ?? 00 00 81 f1 ?? ?? ?? ?? 03 75 08 [0-5] d3 ca [0-5] 30 36 ac [0-5] e2}  //weight: 1, accuracy: Low
        $x_1_3 = {8d 45 d4 29 e0 75 ?? 8b 4d 00 [0-1] 85 c9 74 25 55 89 e5 80 7d 0c 01 75 27 ba ?? ?? ?? ?? 56 52 b9 ?? ?? ?? ?? 31 d1 be ?? 10 00 00 81 f1 ?? ?? ?? ?? 03 75 08 d3 ca 83 fa 00 30 36 ac e2 f6}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Tracur_J_2147682469_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Tracur.gen!J"
        threat_id = "2147682469"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Tracur"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {55 89 e5 59 e8 00 00 00 00 5a 55 89 e5 68 ?? ?? ?? ?? 5a 57 b8 67 10 00 00 68 af 04 00 00 59 83 ed 08 03 45 10 e8 01 00 00 00 c3 66 29 10 83 c0 02 5f 57 47 49 74 02}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 02 00 00 00 eb 10 85 c0 74 02 31 c0 c3 66 29 10 83 c0 02 e2 f8 c3 55 89 e5 68 ?? ?? ?? ?? 5a 57 b8 ?? 10 00 00 68 ?? ?? 00 00 59 83 ed 04 03 45 0c e8 d7 ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

