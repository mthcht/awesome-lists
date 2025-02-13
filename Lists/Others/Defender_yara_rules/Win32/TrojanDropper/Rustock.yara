rule TrojanDropper_Win32_Rustock_O_2147803937_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rustock.O"
        threat_id = "2147803937"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 81 38 4d 5a 68 ?? ?? ?? ?? 60 e8 ?? ?? ff ff 8b 50 10 66 0f ce 60 c7 44 ?? ?? ?? ?? ?? ?? e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {f5 f5 33 44 24 ?? e9 87 00 00 00 83 f8 00 66 c7 44 24 ?? ?? ?? c6 44 24 ?? ?? 60 8d 64 24 ?? 0f 85 ?? ?? 00 00 9c 9c 90 [0-4] 9c e8 00 00 00 00 c7 44 24 ?? ?? ?? 40 00 83 ec f4 68 ?? ?? ?? ?? e8 ?? ?? 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Rustock_R_2147803975_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rustock.R"
        threat_id = "2147803975"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {be c0 38 00 00 3b fe 89 7d f8 0f 82 ?? ?? ?? ?? 6a 04 68 00 30 00 00 56 53 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {76 1d 53 0f b7 1c 0e 03 d3 f7 c2 00 00 01 00 74 07 42 81 e2 ff ff 00 00 46 46 3b f7 72 e5}  //weight: 1, accuracy: High
        $x_1_3 = {74 14 8b 75 f0 8b f8 b9 30 0e 00 00 50 f3 a5 e8 ?? ?? ?? ?? eb 0c}  //weight: 1, accuracy: Low
        $x_1_4 = {83 7e 04 03 75 1b 8b 46 18 38 18 75 14 8b 46 0c 38 18 74 0d ff 75 f0 50 ff 55 08 85 c0 59}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDropper_Win32_Rustock_J_2147804000_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rustock.J"
        threat_id = "2147804000"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 e8 03 00 00 00 33 c0 c3 04 01 01 01 01 60 e9 eb 68}  //weight: 1, accuracy: Low
        $x_1_2 = {e8 09 00 00 00 33 c0 83 c4 44 c3 [0-4] 03 01 01 01 60 eb 68}  //weight: 1, accuracy: Low
        $x_1_3 = {e8 91 fc ff ff 85 c0 74 05 33 f6 46 eb 13 68 ?? ?? ?? ?? 53 e8 7d fc ff ff 8b f0 f7 de 1b f6 f7 de 83 7d 08 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule TrojanDropper_Win32_Rustock_E_2147804098_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rustock.gen!E"
        threat_id = "2147804098"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 13 31 c2 8d 64 24 fc 89 14 24 8f 06 8d 5b 04 83 c6 04 83 e9 01 85 c9 75 19 61 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 80 a2 4a fa 27 eb}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Rustock_B_2147804172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rustock.B"
        threat_id = "2147804172"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 38 00 0f 84 ?? ?? 00 00 80 38 00 74 ?? 81 38 65 6d 33 32 74 03 40 eb}  //weight: 1, accuracy: Low
        $x_1_2 = {66 c7 44 10 ff 5f 00 6a 01 68 ?? ?? 40 00 68 ?? ?? 40 00 ff 15 8c 80 40 00 6a 00 68 80 00 00 00 6a 02 6a 00 6a 00 68 00 00 00 40 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 83 f8 ff 75 14 6a 01 68 ?? ?? 40 00 68 ?? ?? 40 00 ff 15 ?? ?? 40 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_Rustock_L_2147804173_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Rustock.L"
        threat_id = "2147804173"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Rustock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 7e 04 03 75 1b 8b 46 18 38 18 75 14 8b 46 0c 38 18 74 0d ff 75 f0 50 ff 55 08}  //weight: 1, accuracy: High
        $x_1_2 = {3b fe 89 7d f8 0f 82 ?? ?? 00 00 6a 04 68 00 30 00 00 56 53 e8 ?? ?? ?? ?? 3b c3 89 45 f0 05 00 be (00 2e|c0 36) 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

