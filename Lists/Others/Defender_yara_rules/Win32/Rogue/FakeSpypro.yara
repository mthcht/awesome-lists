rule Rogue_Win32_FakeSpypro_136370_0
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {68 4e 5f 87 2a c7 04 24 94 fe 63 50 48 f5 68 73 17 f5 00 68 47 ce f2 d1 83 f8 00 60 66 89 7c 24 04 68 35 d3 81 53 68 a6 2d d7 02 8d 64 24 34 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_1
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s/activate.php?email=%s&code=%s" ascii //weight: 2
        $x_2_2 = {2e 2f 41 76 53 63 61 6e 2e 63 6f 6e 66 00}  //weight: 2, accuracy: High
        $x_2_3 = "virustriggerbinwarning.warningbho.1" ascii //weight: 2
        $x_1_4 = {53 6f 66 74 77 61 72 65 5c 41 76 53 63 61 6e 00}  //weight: 1, accuracy: High
        $x_2_5 = {5c 72 75 6e 6f 6e 63 65 5c 76 69 72 75 73 74 72 69 67 67 65 72 62 69 6e 00}  //weight: 2, accuracy: High
        $x_1_6 = "zibaglertz" ascii //weight: 1
        $x_1_7 = "_getUpdate_verSigs" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_2
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Spyware Protect 2009" wide //weight: 10
        $x_10_2 = "C:\\WINDOWS\\sysguard.exe" wide //weight: 10
        $x_10_3 = "/loads.php" wide //weight: 10
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_3
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Antivirus System PRO" wide //weight: 10
        $x_10_2 = "Software\\AvScan" wide //weight: 10
        $x_3_3 = "http://%s/purchase" wide //weight: 3
        $x_1_4 = "Your system might be at risk" wide //weight: 1
        $x_1_5 = "\\system32\\drivers\\etc\\hosts" wide //weight: 1
        $x_1_6 = "http://%s/loads.php" wide //weight: 1
        $x_1_7 = "http://%s/check" wide //weight: 1
        $x_1_8 = "http://%s/block.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_4
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://spywprotect.com/purchase" wide //weight: 1
        $x_1_2 = "sysguardn.exe" wide //weight: 1
        $x_1_3 = "ForceRemove" wide //weight: 1
        $x_1_4 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "SillyDl BCL" wide //weight: 1
        $x_1_6 = "A program that downloads and may execute or install software without user permission" wide //weight: 1
        $x_1_7 = "MSASCui.exe" wide //weight: 1
        $x_1_8 = "Category Backdoor: This Trojan provides a remote malicious user with access to the victim machine. It is a Windows PE EXE file." wide //weight: 1
        $x_1_9 = "antivirnet.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_5
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {96 58 b9 e7 bf 35 02 01 ca 81 e9 03 bb 35 02 81 c6 21 bd 38 00 81 c6 df ea 0d 00 89 f2 fc 89 f7 52 e9 77 ff ff ff 2d ?? ?? ?? ?? 41 49 e8 72 ff ff ff 83 e9 0a 83 c1 09 85 c9 75 e5 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_6
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {eb 10 8a 10 84 d2 74 0e 40 0f b6 d2 89 04 be 47 03 c2 3b c1 72 ec}  //weight: 1, accuracy: High
        $x_1_2 = "Software\\AvScan" ascii //weight: 1
        $x_1_3 = {70 72 6f 78 79 6c 73 70 2e 64 6c 6c 00 49 6e 73 74 61 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_7
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 57 68 00 ff ff ff 53 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {eb 77 ff 44 24 10 83 7c 24 10 0a 75 3e}  //weight: 2, accuracy: High
        $x_2_3 = {85 d2 75 3c 8b c6 6b c0 0c 8b 88 ?? ?? ?? ?? 8b 90 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 89 44}  //weight: 2, accuracy: Low
        $x_1_4 = {59 59 85 c0 74 36 83 c7 0c 46 81 ff}  //weight: 1, accuracy: High
        $x_1_5 = {37 61 1d 02 a4 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_8
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 53 6a f0 56 ff 15}  //weight: 2, accuracy: High
        $x_2_2 = {eb 67 ff 45 fc 83 7d fc 0a 75 4b}  //weight: 2, accuracy: High
        $x_2_3 = {85 d2 75 3c 8b c6 6b c0 0c 8b 88 ?? ?? ?? ?? 8b 90 ?? ?? ?? ?? 8b 80 ?? ?? ?? ?? 89 44}  //weight: 2, accuracy: Low
        $x_1_4 = {74 39 50 57 e8 ?? ?? ?? ?? 59 59 85 c0 74 36 83 c6 0c}  //weight: 1, accuracy: Low
        $x_1_5 = {37 61 1d 02 a4 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_9
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ff ce fe 8d 44 24 0c 50 ff 74 08 07 e8 18 02 55 50 58 30 00 00 00 00 00 (a0|b0) 02 00 00 10 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 e0 55 50 58 31 00 00 00 00 00 30 03 00 00 (b0|c0) 02 00 00 ?? 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_10
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ff ce fe 8d 44 24 0c 50 ff 74 08 07 e8 20 02 55 50 58 30 00 00 00 00 00 (90 90|a0) 02 00 00 10 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 e0 55 50 58 31 00 00 00 00 00 30 03 00 00 (a0|b0) 02 00 00 ?? 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_11
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ff ce fe 8d 44 24 0c 50 ff 74 08 07 e8 08 02 55 50 58 30 00 00 00 00 00 (90|a0|b0) 02 00 00 10 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 e0 55 50 58 31 00 00 00 00 00 (30|b0|c0) 03 00 00 (a0|b0|c0) 02 00 00 ?? 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_12
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {fe ff ce fe 8d 44 24 0c 50 ff 74 08 07 e8 10 02 55 50 58 30 00 00 00 00 00 (90|a0|b0) 02 00 00 10 00 00 00 00 00 00 00 04 00 00 00 00 00 00 00 00 00 00 00 00 00 00 80 00 00 e0 55 50 58 31 00 00 00 00 00 (30|b0|c0) 03 00 00 (a0|b0|c0) 02 00 00 ?? 03 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_13
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "%s/block.php?r=%s" ascii //weight: 2
        $x_2_2 = "alert-icon-small.gif" wide //weight: 2
        $x_1_3 = "Software\\avsoft" wide //weight: 1
        $x_1_4 = {6a 02 56 68 00 ff ff ff 53 ff 15}  //weight: 1, accuracy: High
        $x_2_5 = "%s/purchase?r=%s" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_14
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 6a 00 6a 80 8b 4d fc 51 ff 15 ?? ?? ?? ?? 6a 00 8d 55 f4 52 68 80 00 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {d8 f9 ff ff ?? 8b ?? 08 8b ?? 08 8b ?? 08 8b ?? 08 8b ?? ?? 8b ?? 2c ff}  //weight: 1, accuracy: Low
        $x_1_3 = {81 7d 0c fa 00 00 00 0f 85 ?? ?? 00 00 8b ?? 08 83 ?? 08 00 75 0a b8 05 40 00 80 e9 ?? ?? 00 00 8b ?? 1c 8b ?? 8b ?? 58}  //weight: 1, accuracy: Low
        $x_2_4 = "Software\\AvScan" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_15
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {6a 02 6a 00 68 00 ff ff ff 8b 4d fc 51 ff 15 ?? ?? ?? ?? 6a 00 8d 55 f4 52 68 00 01 00 00}  //weight: 2, accuracy: Low
        $x_1_2 = {f9 ff ff 51 8b ?? 08 8b ?? 08 8b ?? 08 8b ?? 08 8b ?? ?? 8b ?? 2c ff}  //weight: 1, accuracy: Low
        $x_1_3 = {81 7d 0c fa 00 00 00 0f 85 ?? ?? 00 00 8b ?? 08 83 ?? 08 00 75 0a b8 05 40 00 80 e9 ?? ?? 00 00 8b ?? 1c 8b ?? 8b ?? 58}  //weight: 1, accuracy: Low
        $x_2_4 = "Software\\AvScan" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_16
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {eb 10 8a 10 84 d2 74 0e 40 0f b6 d2 89 04 be 47 03 c2 3b c1 72 ec}  //weight: 2, accuracy: High
        $x_2_2 = "http://%s/loads2.php?r=%s" wide //weight: 2
        $x_1_3 = "Software\\AvScan" wide //weight: 1
        $x_1_4 = "http://%s/check" wide //weight: 1
        $x_1_5 = {73 00 79 00 73 00 67 00 75 00 61 00 72 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_17
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/activate.php?email=" ascii //weight: 1
        $x_1_2 = {53 74 61 72 74 20 41 6e 74 69 76 69 72 75 73 00 2f 73 63 61 6e 00}  //weight: 1, accuracy: High
        $x_1_3 = {61 76 73 75 69 74 65 2e 65 78 65 00 68 74 6d 6c 61 79 6f 75 74 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_4 = {61 76 73 6f 66 74 2e 65 78 65 00 68 74 6d 6c 61 79 6f 75 74 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = {53 6f 66 74 77 61 72 65 5c 61 76 73 (6f|75 69) 00}  //weight: 1, accuracy: Low
        $x_1_6 = {44 6f 77 6e 6c 6f 61 64 20 64 61 74 61 62 61 73 65 00 64 6f 77 6e 6c 6f 61 64 73 2f 63 6f 6d 6d 6f 6e 2f 73 63 72 69 70 74 2e 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_18
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 2e 30 34 00 55 50 58 21 0d 09 08 08 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 06 00 26 0a 00 e3 01 2e 74 65 78 74 00 ?? 00 (48|5a|53|51) (21|15) 02 00 00 10 00 00 (48|5a|53|51) (21|15) 02 00 00 10 00 00 00 00 00 00 00 00 00 00 00 00 00 00 20 00 00 60 2e 72 64 61 74 61 00 00 (4c|14|54) 01 00 00 00 (40|30) 02 00 (4c|14|54) 01 00 00 00 (40|30) 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 40 2e 64 61 74 61 00 ?? 00 (a8|20) (1e|15) 02 00 00 (50|40) 02 00 (a8|20) (1e|15) 02 00 00 (50|40) 02 00 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_19
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {53 6f 66 74 77 61 72 65 5c 73 73 75 69 74 65 00}  //weight: 2, accuracy: High
        $x_2_2 = {53 6f 66 74 77 61 72 65 5c 61 76 69 73 00}  //weight: 2, accuracy: High
        $x_1_3 = "<img src=\"http://*BSURL*/images/" ascii //weight: 1
        $x_1_4 = "virusinfo-active.gif" wide //weight: 1
        $x_1_5 = "rslt-table-head-bg.gif" wide //weight: 1
        $x_1_6 = "banner-get-protection.gif" wide //weight: 1
        $x_1_7 = {74 31 3d 43 4f 4e 4e 74 00}  //weight: 1, accuracy: High
        $x_1_8 = {74 38 3d 48 45 41 44 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_20
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {72 75 6e 6f 6e 63 65 65 78 5c 76 69 72 75 73 74 72 69 67 67 65 72 62 69 6e 00}  //weight: 2, accuracy: High
        $x_2_2 = "'img/icon-malware-err.gif'" wide //weight: 2
        $x_2_3 = {53 6f 66 74 77 61 72 65 5c 61 76 73 75 69 74 65 00}  //weight: 2, accuracy: High
        $x_2_4 = {53 65 53 68 75 74 64 6f 77 6e 50 72 69 76 69 6c 65 67 65 00 44 6f 20 79 6f 75 20 77 61 6e 74 20 74 72 65 62 6f 6f 74 20 6e 6f 77 3f [0-4] 52 65 62 6f 6f 71 75 65 73 74 69 6f 6e 00}  //weight: 2, accuracy: Low
        $x_2_5 = "%sactivate.php?email=%s" wide //weight: 2
        $x_1_6 = {56 4d 61 6c 75 6d 20 41 57 53 00}  //weight: 1, accuracy: High
        $x_1_7 = {53 69 6c 6c 79 44 6c 20 42 43 4c 00}  //weight: 1, accuracy: High
        $x_2_8 = "Do You want to reboot the system now?" ascii //weight: 2
        $x_2_9 = "'activButton'" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_21
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 85 f9 00 00 00 e8 ?? ?? 00 00 3d ?? ?? 00 00 0f 8d e9 00 00 00 c7 45 f8 06 02 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {85 c0 75 10 e8 ?? ?? ?? ?? 3d ?? ?? 00 00 0f 8d ?? ?? 00 00 c7 45 f8 06 02 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {81 7d 0c fa 00 00 00 0f 85 3f 02 00 00 8b 45 08 83 78 08 00 75 0a b8 05 40 00 80 e9 2e 02 00 00 8b 4d 1c 8b 11 8b 42 58 8b 48 08 89 4d fc}  //weight: 1, accuracy: High
        $x_1_4 = "Software\\AvScan" wide //weight: 1
        $x_1_5 = "{C9C42510-9B21-41c1-9DCD-8382A2D07C61}" wide //weight: 1
        $x_1_6 = "{ABD42510-9B22-41cd-9DCD-8182A2D07C63}" wide //weight: 1
        $x_1_7 = {61 00 72 00 63 00 68 00 2e 00 00 00 3f 00 71 00 3d 00 00 00 73 00 70 00 79 00 77 00 61 00 72 00 65 00 00 00 70 00 72 00 6f 00 74 00 65 00 63}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Rogue_Win32_FakeSpypro_136370_22
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "icon-malware-err.gif" wide //weight: 5
        $x_5_2 = "rezult-table-border-bot.gif" wide //weight: 5
        $x_5_3 = "<a href=\"{PURCHASE}" ascii //weight: 5
        $x_5_4 = {53 6f 66 74 77 61 72 65 5c 61 76 53 6f 66 54 00}  //weight: 5, accuracy: High
        $x_5_5 = {53 6f 66 74 77 61 72 65 5c 41 56 53 75 69 74 45 00}  //weight: 5, accuracy: High
        $x_5_6 = {5f 00 76 00 69 00 72 00 75 00 73 00 54 00 61 00 62 00 6c 00 65 00 00 00}  //weight: 5, accuracy: High
        $x_5_7 = {53 6f 66 74 77 61 72 65 5c 41 6e 74 69 76 69 72 75 73 20 53 6f 66 74 20 50 6c 61 74 69 6e 75 6d 00}  //weight: 5, accuracy: High
        $x_5_8 = "downloads/installer_avsoft/" ascii //weight: 5
        $x_5_9 = {41 6e 74 69 76 69 72 75 73 20 53 6f 66 74 20 50 6c 61 74 69 6e 75 6d 2e 6c 6e 6b 00}  //weight: 5, accuracy: High
        $x_5_10 = {72 00 6f 00 6f 00 74 00 5c 00 53 00 65 00 63 00 75 00 72 00 69 00 74 00 79 00 43 00 65 00 6e 00 74 00 65 00 72 00 00 00}  //weight: 5, accuracy: High
        $x_5_11 = {53 6f 66 74 77 61 72 65 5c 41 56 53 6f 6c 75 74 69 6f 6e 00}  //weight: 5, accuracy: High
        $x_5_12 = {5f 00 76 00 69 00 72 00 74 00 62 00 6c 00 00 00}  //weight: 5, accuracy: High
        $x_1_13 = "antispyware-scan." ascii //weight: 1
        $x_1_14 = "members.antivirget.com" ascii //weight: 1
        $x_1_15 = {41 74 6c 41 78 57 69 6e 4c 69 63 38 30 00}  //weight: 1, accuracy: High
        $x_1_16 = {5f 00 67 00 65 00 74 00 55 00 70 00 64 00 61 00 74 00 65 00 5f 00 6c 00 61 00 6d 00 70 00 44 00 62 00 53 00 74 00 61 00 74 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_17 = {5f 00 6c 00 69 00 63 00 45 00 6d 00 61 00 69 00 6c 00 00 00}  //weight: 1, accuracy: High
        $x_1_18 = "Category Virus: It is a malicious tool" wide //weight: 1
        $x_1_19 = "Advanced Stealth Email Redirector" ascii //weight: 1
        $x_1_20 = "members.getavnow.com" ascii //weight: 1
        $x_1_21 = {76 69 72 75 73 72 65 73 70 6f 6e 73 65 6c 61 62 32 30 30 39 00}  //weight: 1, accuracy: High
        $x_5_22 = {53 6f 66 74 77 61 72 65 5c 53 6f 6c 75 74 69 6f 6e 41 56 00}  //weight: 5, accuracy: High
        $x_5_23 = {41 6e 74 69 76 69 72 20 53 6f 6c 75 74 69 6f 6e 20 50 72 6f 00}  //weight: 5, accuracy: High
        $x_5_24 = "IconMalwareErr.Gif" wide //weight: 5
        $x_1_25 = {5c 72 75 6e 6f 6e 63 65 5c 76 69 72 75 73 74 72 69 67 67 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            ((3 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule Rogue_Win32_FakeSpypro_136370_23
{
    meta:
        author = "defender2yara"
        detection_name = "Rogue:Win32/FakeSpypro"
        threat_id = "136370"
        type = "Rogue"
        platform = "Win32: Windows 32-bit platform"
        family = "FakeSpypro"
        severity = "26"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " = document.getElementById('virusTable')" ascii //weight: 1
        $x_1_2 = "dialog = document.getElementById('purchaseDialog');" ascii //weight: 1
        $x_1_3 = "lt-table-head-bg.gif" ascii //weight: 1
        $x_1_4 = "purchase-active.gif" ascii //weight: 1
        $x_1_5 = "virusinfo-active.gif" ascii //weight: 1
        $x_1_6 = "elseif InStr(1, val, \"asam.exe\", 1) then" ascii //weight: 1
        $x_1_7 = "fso.MoveFile path, path & \".vir\"" ascii //weight: 1
        $x_1_8 = "onclick=\"onPurchaseDialog(0);" ascii //weight: 1
        $x_1_9 = {4b 69 6c 6c 42 79 50 72 6f 63 [0-2] 22 25 5c 5b 30 2d 39 5d 5b 30 2d 39 5d 5b 30 2d 39 5d 5b 30 2d 39 5d 25 2e 65 78 65 22 2c 20 22 46 61 6b 65 2e 53 65 63 75 72 69 74 79 20 54 6f 6f 6c 22}  //weight: 1, accuracy: Low
        $x_1_10 = "icon-malware-red.gif" ascii //weight: 1
        $x_1_11 = "header-perfoming-scan.gif" ascii //weight: 1
        $x_1_12 = "<img src=\"http://*BSURL*/images/" ascii //weight: 1
        $x_1_13 = "hdrperfscan.gif" ascii //weight: 1
        $x_1_14 = "_h_d_perf_scn.gif" ascii //weight: 1
        $x_1_15 = "Category Backdoor: It is a critical vulnerability" wide //weight: 1
        $x_1_16 = "scanButtonClick" ascii //weight: 1
        $x_1_17 = "banner-get-protection.gif" ascii //weight: 1
        $x_1_18 = "Category Virus: It is a malicious tool" wide //weight: 1
        $x_1_19 = "bg-scanpercent.gif" ascii //weight: 1
        $x_2_20 = "This is Backdoor: It is a critical vulnerability" wide //weight: 2
        $x_2_21 = "names = ['Win32/Nuqel.E', 'BankerFox.A'," ascii //weight: 2
        $x_2_22 = {33 d2 b9 e8 03 00 00 f7 f1 89 44 24 ?? 3b c7 72 ?? 83 ff 78 7d ?? 3b 3d ?? ?? ?? ?? 73 ?? 6a 78 58 2b c7 69 c0 e8 03 00 00 50 ff d6}  //weight: 2, accuracy: Low
        $x_1_23 = "background:url('bigalert.gif') no-repeat;" ascii //weight: 1
        $x_1_24 = "Windows system directory: %System%\\kavo.exe" wide //weight: 1
        $x_1_25 = "bg-progress-scan-bar.gif" wide //weight: 1
        $x_1_26 = "vinfact.gif" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

