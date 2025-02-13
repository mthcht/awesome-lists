rule PWS_Win32_Simda_A_2147645704_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Simda.gen!A"
        threat_id = "2147645704"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_4_1 = {1b c0 25 bd 5a 34 12 50 6a 07 68 00 00 00 c0 ff 75 08 ff 15}  //weight: 4, accuracy: High
        $x_2_2 = {b8 69 75 68 00 84 d2 74 10}  //weight: 2, accuracy: High
        $x_1_3 = "name=%s&port=%u" ascii //weight: 1
        $x_1_4 = "Opera\\profile\\wand.dat" ascii //weight: 1
        $x_1_5 = "Opera\\Opera\\typed_history.xml" ascii //weight: 1
        $x_1_6 = "&config=ok" ascii //weight: 1
        $x_1_7 = "&inject=ok" ascii //weight: 1
        $x_1_8 = "!new_config" ascii //weight: 1
        $x_1_9 = "iexplore.exe|opera.exe|java.exe" ascii //weight: 1
        $x_1_10 = "keylog.txt" ascii //weight: 1
        $x_1_11 = {69 64 3d 25 73 26 76 65 72 3d ?? ?? ?? ?? ?? 26 75 70 3d 25 75 26 6f 73 3d 25 30 33 75 26 72 69 67 68 74 73 3d 25 73 26 6c 74 69 6d 65 3d 25 73 25 64}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Simda_K_2147650930_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Simda.K"
        threat_id = "2147650930"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iexplore.exe|" ascii //weight: 1
        $x_1_2 = "botid=%s&ver=" ascii //weight: 1
        $x_1_3 = "slipknot1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Simda_L_2147650977_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Simda.L"
        threat_id = "2147650977"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "[BACKSPACE]" ascii //weight: 1
        $x_1_2 = {5c 6b 65 79 6c 6f 67 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_3 = {8a 0c 30 80 f1 62 88 0c 30 40 3b c7 72 f2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Simda_AF_2147663891_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Simda.AF"
        threat_id = "2147663891"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "hid=%s&username=SYSTEM&compname=%s&bot_version=" ascii //weight: 2
        $x_2_2 = {63 6f 6d 6d 61 6e 64 3d 62 63 5f 61 63 74 69 76 61 74 65 26 69 70 3d 00 26 70 6f 72 74 3d 00 00}  //weight: 2, accuracy: High
        $x_1_3 = {26 63 76 76 32 3d 00 00 26 63 76 76 32 3d 26 00}  //weight: 1, accuracy: High
        $x_1_4 = {41 67 61 76 61 5f 43 6c 69 65 6e 74 2e 69 6e 69 00 00 00 00 41 67 61 76 61 5f 6b 65 79 73 00 00 6b 65 79 73 5f 70 61 74 68 2e 74 78 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {5c 6d 61 73 6b 73 32 2e 6b 65 79 00 6d 61 73 6b 73 2e 6b 65 79 00}  //weight: 1, accuracy: High
        $x_1_6 = {6b 65 79 73 39 39 2e 7a 69 70 00 00 70 61 74 68 39 39 2e 74 78 74 00 00 5c 63 72 79 70 74 6f 5c}  //weight: 1, accuracy: High
        $x_1_7 = {26 6b 6e 6f 63 6b 5f 77 6f 5f 6c 6f 67 3d 00}  //weight: 1, accuracy: High
        $x_1_8 = {63 6f 6d 6d 61 6e 64 3d 69 6e 6a 65 63 74 26 64 61 74 61 3d 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule PWS_Win32_Simda_F_2147678578_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Simda.gen!F"
        threat_id = "2147678578"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Simda"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {47 6c 6f 62 c7 45 ?? 61 6c 5c 4d c7 45 ?? 69 63 72 6f c7 45 ?? 73 6f 66 74 c7 45 ?? 53 79 73 65 c7 45 ?? 6e 74 65 72 c7 45 ?? 47 61 74 65 66 c7 ?? f4 ?? 00 ff 15}  //weight: 1, accuracy: Low
        $x_1_2 = "dabetreswe5puphEgawrede3reswusa" ascii //weight: 1
        $x_1_3 = "&command=bc_activate&status=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

