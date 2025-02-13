rule Trojan_Win32_FakeIA_C_133717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.C"
        threat_id = "133717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c6 00 46 8b 03 c6 40 01 49 8b 03 c6 40 02 52 8b 03 c6 40 03 45 8b 03 c6 40 04 46 8b 03 c6 40 05 4f 8b 03 c6 40 06 58 8b 03 c6 40 07 2e}  //weight: 1, accuracy: High
        $x_1_2 = {c6 00 49 8b 03 c6 40 01 45 8b 03 c6 40 02 58 8b 03 c6 40 03 50 8b 03 c6 40 04 4c 8b 03 c6 40 05 4f 8b 03 c6 40 06 52 8b 03 c6 40 07 45 8b 03 c6 40 08 2e}  //weight: 1, accuracy: High
        $x_1_3 = {c6 00 4f 8b 03 c6 40 01 50 8b 03 c6 40 02 45 8b 03 c6 40 03 52 8b 03 c6 40 04 41 8b 03 c6 40 05 2e}  //weight: 1, accuracy: High
        $x_4_4 = {7e 25 bf 01 00 00 00 8d 45 f8 8b 55 fc 8a 54 3a ff 80 f2 ff e8 ?? ?? ff ff 8b 55 f8 8b c6 e8 ?? ?? ff ff}  //weight: 4, accuracy: Low
        $x_5_5 = {3c 74 69 74 6c 65 3e 49 6e 73 65 63 75 72 65 20 42 72 6f 77 73 69 6e 67 3a 20 4e 61 76 69 67 61 74 69 6f 6e 20 6f 6e 20 68 6f 6c 64 3c 2f 74 69 74 6c 65 3e 0d 0a}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 3 of ($x_1_*))) or
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((1 of ($x_5_*) and 1 of ($x_4_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeIA_D_134174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.D"
        threat_id = "134174"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {45 6e 61 62 6c 65 20 50 72 6f 74 65 63 74 69 6f 6e 00 00 00 42 55 54 54 4f 4e 00 00 55 6e 62 6c 6f 63 6b 00 4b 65 65 70 20 42 6c 6f 63 6b 69 6e 67 00 00 00 43 6c 69 63 6b 20 74 6f 20 64 6f 77 6e 6c 6f 61 64 20 61 6e 64 20 61 63 74 69 76 61 74 65 20 70 72 6f 74 65 63 74 69 6f 6e 2e 00 00 53 54 41 54 49 43 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeIA_E_134930_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.E"
        threat_id = "134930"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {45 6e 61 62 6c 65 20 50 72 6f 74 65 63 74 69 6f 6e 00 00 00 42 55 54 54 4f 4e 00 00 55 6e 62 6c 6f 63 6b 00 4b 65 65 70 20 42 6c 6f 63 6b 69 6e 67}  //weight: 1, accuracy: High
        $x_1_2 = {53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 41 6c 65 72 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {53 45 5f 53 48 55 54 44 4f 57 4e 5f 4e 41 4d 45 [0-16] 53 48 55 54 44 4f 57 4e 20 2d 72 20 2d 66 20 2d 74 [0-16] 64 65 6c [0-16] 2e 62 61 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeIA_G_137084_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.G"
        threat_id = "137084"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Windows Security Alert" ascii //weight: 1
        $x_1_2 = "Security Center Alert" ascii //weight: 1
        $x_7_3 = {c6 03 48 c6 43 01 69 c6 43 02 67 c6 43 03 68 c6 43 04 00 8d 85 ?? ?? ff ff 8b d3 e8 ?? ?? ?? ?? 8b 85 ?? ?? ff ff e8 ?? ?? ?? ?? 50 53 6a 76 6a 7d 56 e8}  //weight: 7, accuracy: Low
        $x_3_4 = {7e 25 bf 01 00 00 00 8d 45 f8 8b 55 fc 8a 54 3a ff 80 f2 ff e8 ?? ?? ff ff 8b 55 f8 8b c6 e8 ?? ?? ff ff}  //weight: 3, accuracy: Low
        $x_3_5 = {84 c0 74 36 8b 15 ?? ?? ?? ?? 83 ea 04 b8 ?? ?? ?? ?? b9 04 00 00 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 10 a1 ?? ?? ?? ?? 83 c0 04 50 a1 ?? ?? ?? ?? 83 e8 04 50 e8}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*))) or
            ((1 of ($x_7_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeIA_F_137085_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.F"
        threat_id = "137085"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "115"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 100
        $x_10_2 = {83 e8 04 b9 04 00 00 00 e8 ?? ?? ?? ?? 68 ?? ?? ?? 00 6a 40 a1 ?? ?? ?? 00 83 c0 04}  //weight: 10, accuracy: Low
        $x_2_3 = {53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 41 6c 65 72 74 00}  //weight: 2, accuracy: High
        $x_1_4 = {75 73 61 6e 61 7a 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_5 = {72 61 73 69 6d 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {73 69 6e 61 73 68 69 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_7 = {6d 61 6e 6f 6c 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_8 = {78 65 72 6b 73 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 1 of ($x_10_*) and 1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeIA_J_140908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.J"
        threat_id = "140908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 50 50 44 41 54 41 5c ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_2 = {c3 90 72 00 65 00 61 00 6c 00 74 00 65 00 6b 00 73 00}  //weight: 1, accuracy: High
        $x_1_3 = "winlogons.exe" wide //weight: 1
        $x_1_4 = "ZwQuerySystemInformation" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeIA_I_140910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.I"
        threat_id = "140910"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f0 89 3e 8b d6 83 c2 05 8b c3 e8 ?? ?? ?? ?? 8b d6 83 c2 04 88 02 c6 03 e9}  //weight: 1, accuracy: Low
        $x_1_2 = {8a 54 3a ff (80 f2|32 55) ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b c6 e8 ?? ?? ?? ?? 47 4b 75 e0}  //weight: 1, accuracy: Low
        $x_1_3 = {83 fb 05 72 ?? 8b cb 8b d5 8b c7 e8 ?? ?? ?? ?? 8b c7 8b d0 03 d3 c6 02 e9}  //weight: 1, accuracy: Low
        $x_1_4 = {50 6a 03 e8 ?? ?? ?? ?? 6a ff e8 ?? ?? ?? ?? c3 8d 40 00 53 51 b8 ?? ?? ?? ?? 8b 10 c6 02 ?? 8b 10 c6 42 01 ?? 8b 10}  //weight: 1, accuracy: Low
        $x_1_5 = {83 38 06 75 15 68 ?? ?? ?? ?? 8b 43 3c 50 e8 ?? ?? ?? ?? 85 c0 0f 94 c0 eb 13 68 ?? ?? ?? ?? 8b 43 3c 50 e8 ?? ?? ?? ?? 85 c0 0f 94 c0 84 c0 74 0e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_FakeIA_K_141057_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.K"
        threat_id = "141057"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {49 6e 62 6f 75 6e 64 00 [0-12] 41 6c 6c 6f 77 20 74 68 69 73 20 49 50 00 [0-12] 42 6c 6f 63 6b 20 74 68 69 73 20 49 50 00}  //weight: 2, accuracy: Low
        $x_2_2 = {66 00 72 00 6d 00 50 00 44 00 32 00 30 00 30 00 39 00 41 00 6c 00 65 00 72 00 74 00 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {61 6c 6c 6f 77 74 68 69 73 70 6f 72 74 00 [0-3] 62 6c 6f 63 6b 61 6c 6c 69 70 73 68 6f 76 65 72 00}  //weight: 1, accuracy: Low
        $x_2_4 = "SOFTWARE\\Microsoft\\PDefender" ascii //weight: 2
        $x_1_5 = {41 00 4c 00 4c 00 4f 00 57 00 54 00 48 00 49 00 53 00 50 00 4f 00 52 00 54 00 48 00 4f 00 56 00 45 00 52 00 0b 00 42 00 4c 00 4f 00 43 00 4b 00 41 00 4c 00 4c 00 49 00 50 00 53 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeIA_L_142962_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.L"
        threat_id = "142962"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {eb a1 5e 5b 8b e5 5d c3 00 00 00 53 65 63 75 72 69 74 79 20 43 65 6e 74 65 72 20 41 6c 65 72 74 00 00 00 53 83 c4 f8 8b d8 eb 18}  //weight: 10, accuracy: High
        $x_1_2 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_FakeIA_O_144767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.O"
        threat_id = "144767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "http://www.pdefender2009.com/buy.php" ascii //weight: 10
        $x_10_2 = {ff ff ff ff 24 00 00 00 97 8b 8b 8f c5 d0 d0 88 88 88 d1 8f 9b 9a 99 9a 91 9b 9a 8d cd cf cf c6 d1 9c 90 92 d0 9d 8a 86 d1 8f 97 8f 00 00 00 00}  //weight: 10, accuracy: High
        $x_1_3 = {ff ff ff ff 13 00 00 00 ac b7 aa ab bb b0 a8 b1 df d2 8d df d2 99 df d2 8b df cf 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 50 50 44 41 54 41 5c [0-10] 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_5 = {c6 02 4c 8b 10 c6 42 01 53 8b 10 [0-48] 50 6a 00 6a 00 e8 ?? ?? ff ff 8b d8 e8 ?? ?? ff ff 85 c0 75 16 54 6a 00 6a 00 68 ?? ?? ?? ?? 6a 00 6a 00 e8 62 89 ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakeIA_P_146261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakeIA.P!dll"
        threat_id = "146261"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeIA"
        severity = "Critical"
        info = "dll: Dynamic Link Library component of a malware"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 50 50 44 41 54 41 5c [0-10] 2e 67 69 66}  //weight: 1, accuracy: Low
        $x_1_2 = {ff ff ff ff 13 00 00 00 ac b7 aa ab bb b0 a8 b1 df d2 8d df d2 99 df d2 8b df cf 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 10 c6 02 ?? 8b 10 c6 42 01 ?? 8b 10 c6 42 02 [0-96] 8b 10 c6 42 ?? 00 8b 08 33 d2 33 c0 e8 ?? ?? ff ff 8b d8 e8 ?? ?? ff ff 85 c0 75 17 54 6a 00 6a 00 68 58 c3 40 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 5a 5b c3}  //weight: 1, accuracy: Low
        $x_1_4 = {8a 54 3a ff (80 f2|32 55) ?? e8 ?? ?? ?? ?? 8b 55 ?? 8b c6 e8 ?? ?? ?? ?? 47 4b 75 e0}  //weight: 1, accuracy: Low
        $x_1_5 = {83 fb 05 72 ?? 8b cb 8b d5 8b c7 e8 ?? ?? ?? ?? 8b c7 8b d0 03 d3 c6 02 e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

