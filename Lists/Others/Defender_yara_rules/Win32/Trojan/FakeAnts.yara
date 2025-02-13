rule Trojan_Win32_FakeAnts_122479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 74 24 0e 8a f1 28 36 81 7c 24 0a a5 26 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 74 24 0e 00 36 ff 44 24 0e d1 e9 d1 e9 d1 e9}  //weight: 1, accuracy: High
        $x_1_3 = {72 b2 ff 44 24 0a 81 7c 24 0a 75 27 00 00 76 8f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAnts_122479_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a c8 80 c1 51 30 88 ?? ?? 00 10 83 c0 01 3d}  //weight: 2, accuracy: Low
        $x_2_2 = {75 31 83 c6 04 81 fe ?? ?? ?? ?? 72 e4 8b 44 24 24 8b 4c 24 20 8b 54 24 1c}  //weight: 2, accuracy: Low
        $x_1_3 = {64 6f 5f 64 6c 6c 2e 64 6c 6c 00 49}  //weight: 1, accuracy: High
        $x_1_4 = {77 69 6e 6c 6f 67 6f 6e 2e 73 79 73 00}  //weight: 1, accuracy: High
        $x_3_5 = {8b 7c 24 10 b9 06 00 00 00 be 38 20 40 00 f3 a5 17 00 30 20 40 00 ?? ?? ?? ?? ?? 10 30 40 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeAnts_122479_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {53 8b dc 83 ec 20 c7 44 24 ?? 00 00 00 00 b8 ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? 00 00 00 00 8b 7c 24 ?? 28 07 81 7c 24 04 ?? 27 00 00 74 06 8b 7c 24 ?? 00 07 ff 44 24 ?? c1 e8 08 ff 44 24 ?? 83 7c 24 ?? 04 75 0d b8 ?? ?? ?? ?? c7 44 24 ?? 00 00 00 00 81 7c 24 ?? ?? ?? ?? ?? 72 c1 ff 44 24 ?? 81 7c 24 ?? ?? ?? 00 00 76 9e 8b e3 5b}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAnts_122479_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {27 00 00 74 06 2b 00 83 ec ?? c7 44 24 ?? ?? ?? 00 00 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? 00 00 00 00 8b ?? 24 ?? 28 ?? 81 7c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {27 00 00 74 06 8b 7c 24 ?? 00 ?? ff 44 24 ?? c1 ?? 08 ff 44 24 ?? 83 7c 24 ?? 04 75 0d ?? ?? ?? ?? ?? c7 44 24 ?? 00 00 00 00 81 7c 24 ?? ?? ?? ?? ?? 72 c1 ff 44 24 ?? 81 7c 24}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeAnts_122479_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {5c 63 6f 6f 6b 69 65 73 2e 74 78 74 00 00 00 00 50 61 74 68 00 00 00 00 50 72 6f 66 69 6c 65 00 47 65 6e 65 72 61 6c 00 53 74 61 72 74 57 69 74 68 4c 61 73 74 50 72 6f 66 69 6c 65 00 00 00 00 70 72 6f 66 69 6c 65 73 2e 69 6e 69 00 00 00 00}  //weight: 2, accuracy: High
        $x_2_2 = {3f 70 63 5f 69 64 3d 25 64 26 61 63 74 69 6f 6e 3d 25 64 26 74 79 70 65 3d 25 73 26 61 62 62 72 3d 25 73 00}  //weight: 2, accuracy: High
        $x_1_3 = {41 72 65 20 79 6f 75 20 61 62 73 6f 6c 75 74 65 6c 79 20 73 75 72 65 20 79 6f 75 20 64 6f 20 4e 4f 54 20 77 61 6e 74 20 74 6f 20 63 6f 6e 74 69 6e 75 65 3f 00 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeAnts_122479_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_11_1 = {57 8b fc 83 ec 0c c7 44 24 17 00 00 00 00 b9 ?? ?? ?? ?? c7 44 24 1c ?? ?? ?? ?? c7 44 24 26 00 00 00 00 8b 74 24 1c 28 0e 81 7c 24 17 ?? ?? ?? ?? 74 06 8b 74 24 1c 00 0e ff 44 24 1c c1 e9 08 ff 44 24 26 83 7c 24 26 04 75 0d b9 ?? ?? ?? ?? c7 44 24 26 00 00 00 00 81 7c 24 1c ?? ?? ?? ?? 72 c1 ff 44 24 17 81 7c 24 17 ?? ?? ?? ?? 76 9e 8b e7 5f}  //weight: 11, accuracy: Low
        $x_11_2 = {8b 04 24 66 31 c0 8b 10 81 f2 ?? ?? 00 00 66 81 fa ?? ?? 74 16 2d 00 08 00 00 2d 00 08 00 00 eb e5 ad 35 ?? ?? ?? ?? ab e2 f7 c3 89 c5 b8 ?? ?? ?? ?? 6a 00 ff 54 05 00 69 d2 00 10 00 00 c1 e2 04 83 c4 04 29 c0 8d 88 2c 03 00 00 89 cb c3}  //weight: 11, accuracy: Low
        $x_11_3 = {5e 8b 3e be ?? ?? ?? ?? 01 fe b9 ?? ?? ?? ?? 31 d2 f9 8a 16 83 fa 00 74 0b 80 f2 ?? 83 fa 00 74 03 88 16 f8 f9 46 e2 e9 f8}  //weight: 11, accuracy: Low
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_FakeAnts_122479_6
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "MiTeC_Routines" ascii //weight: 1
        $x_1_2 = "CommonAltStartUp=" ascii //weight: 1
        $x_2_3 = "new Array(\"Do you want to continue browsing unprotected?\"" ascii //weight: 2
        $x_2_4 = "Threat of virus attack</div>" ascii //weight: 2
        $x_2_5 = "disabled: high probability of virus" ascii //weight: 2
        $x_2_6 = "your private inforrmation" ascii //weight: 2
        $x_6_7 = {5a 2b be 9c 91 be be be b7 7b 44 b8 75 37 b9 77 39 b8 74 36 b6 71 31 b3 6c 2a b0 67 22 ae 62 1c ac 5f 16 ab 5d 14 aa 5a 11 a8 59 0e a7 58 0d a7}  //weight: 6, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeAnts_122479_7
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {26 00 00 74 06 8b 2b 00 83 ec ?? c7 44 24 ?? ?? ?? 00 00 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? 00 00 00 00 8b ?? 24 ?? 28 ?? 81 7c 24}  //weight: 1, accuracy: Low
        $x_1_2 = {27 00 00 74 06 8b 2b 00 83 ec ?? c7 44 24 ?? ?? ?? 00 00 ?? ?? ?? ?? ?? c7 44 24 ?? ?? ?? ?? ?? c7 44 24 ?? 00 00 00 00 8b ?? 24 ?? 28 ?? 81 7c 24}  //weight: 1, accuracy: Low
        $x_1_3 = {26 00 00 74 06 8b ?? 24 ?? 00 ?? ff 44 24 ?? c1 [0-5] ff 44 24 ?? 83 7c 24 ?? 04 75 0d ?? ?? ?? ?? ?? c7 44 24 ?? 00 00 00 00 81 7c 24 ?? ?? ?? ?? ?? 72 ?? ff 44 24 ?? 81 7c 24 ?? ?? 27 00 00}  //weight: 1, accuracy: Low
        $x_1_4 = {27 00 00 74 06 8b ?? 24 ?? 00 ?? ff 44 24 ?? c1 [0-5] ff 44 24 ?? 83 7c 24 ?? 04 75 0d ?? ?? ?? ?? ?? c7 44 24 ?? 00 00 00 00 81 7c 24 ?? ?? ?? ?? ?? 72 ?? ff 44 24 ?? 81 7c 24 ?? ?? 27 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_Win32_FakeAnts_122479_8
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "http://doctor-antivirus.com/presalepage/" wide //weight: 5
        $x_5_2 = {45 00 53 00 4f 00 46 00 54 00 57 00 41 00 52 00 45 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 43 00 75 00 72 00 72 00 65 00 6e 00 74 00 56 00 65 00 72 00 73 00 69 00 6f 00 6e 00 5c 00 52 00 75 00 6e 00 5c [0-8] 44 00 6f 00 63 00 74 00 6f 00 72 00 20 00 41 00 6e 00 74 00 69 00 76 00 69 00 72 00 75 00 73 00 20 00 32 00 30 00 30 00 38}  //weight: 5, accuracy: Low
        $x_1_3 = "Protect your PC from violent virus attack!" wide //weight: 1
        $x_1_4 = "This function provides secure protection against self-restoring" wide //weight: 1
        $x_1_5 = "antivirus.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeAnts_122479_9
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeAnts"
        threat_id = "122479"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeAnts"
        severity = "9"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_15_1 = {80 3e 00 75 ed 31 ?? 74 17 [0-21] 5a [0-3] 42 [0-3] 52 [0-5] (ba 00 00|31 d2) eb d2 30 00 [0-10] 02 16 [0-10] (c1 ca|c1 c2) [0-6] 81}  //weight: 15, accuracy: Low
        $x_15_2 = {80 3f 00 75 ed 31 ?? 74 17 [0-21] 5a [0-3] 42 [0-3] 52 [0-5] (ba 00 00|31 d2) eb d2 30 00 [0-10] 02 17 [0-10] (c1 ca|c1 c2) [0-6] 81}  //weight: 15, accuracy: Low
        $x_15_3 = {80 3f 00 75 ef 31 ?? 83 f9 00 74 11 [0-16] 59 41 51 [0-5] (b9 00 00|31 c9) eb d7 2a 00 [0-10] 02 0f [0-5] c1 (c9|c1) [0-6] 81}  //weight: 15, accuracy: Low
        $x_15_4 = {80 3e 00 75 ef 31 ?? 83 f9 00 74 11 [0-16] 59 41 51 [0-5] (b9 00 00|31 c9) eb d7 2a 00 [0-10] 02 0e [0-5] c1 (c9|c1) [0-6] 81}  //weight: 15, accuracy: Low
        $x_15_5 = {80 3f 00 75 ef 31 ?? 83 f8 00 74 17 [0-16] 58 [0-3] 40 [0-3] 50 [0-16] (b8 00 00|31 c0) eb 33 00 [0-10] 02 07 [0-5] c1 (c0|c8) [0-6] 81}  //weight: 15, accuracy: Low
        $x_15_6 = {80 3e 00 75 ef 31 ?? 83 f8 00 74 17 [0-16] 58 [0-3] 40 [0-3] 50 [0-16] (b8 00 00|31 c0) eb 33 00 [0-10] 02 06 [0-5] c1 (c0|c8) [0-6] 81}  //weight: 15, accuracy: Low
        $x_5_7 = "http://doctor-antivirus.com/" ascii //weight: 5
        $x_2_8 = "Protect my PC now" ascii //weight: 2
        $x_2_9 = "Get full real-time protection" ascii //weight: 2
        $x_2_10 = "ShellExecuteW" ascii //weight: 2
        $x_2_11 = "http://doctorantivirus2008a.com/support.php" ascii //weight: 2
        $x_2_12 = "Backdoor.Agobot.gen" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 5 of ($x_2_*))) or
            ((1 of ($x_15_*))) or
            (all of ($x*))
        )
}

