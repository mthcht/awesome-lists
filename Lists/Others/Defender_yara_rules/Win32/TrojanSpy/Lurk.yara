rule TrojanSpy_Win32_Lurk_A_2147648844_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lurk.A"
        threat_id = "2147648844"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lurk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 33 c9 68 ?? ?? ?? ?? c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Lurk_A_2147648844_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lurk.A"
        threat_id = "2147648844"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lurk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "&aql=&oq=" ascii //weight: 1
        $x_1_2 = {25 73 25 73 25 64 2e 63 6d 64 00}  //weight: 1, accuracy: High
        $x_1_3 = "{118BEDCC-A901-4203-B4F2-ADCB957D1887}" ascii //weight: 1
        $x_1_4 = {ff d3 6a 04 8d 45 fc 50 6a 05 57 ff d6}  //weight: 1, accuracy: High
        $x_1_5 = {83 f8 50 75 05 33 c0 40 5e c3 56 ff 15 ?? ?? ?? ?? ff 74 24 08 ff 15}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanSpy_Win32_Lurk_E_2147657784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lurk.E"
        threat_id = "2147657784"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lurk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 59 3b fb 74 ?? 56 6a 40 68 00 30 00 00 ff 75 ?? 53 ff 75 ?? ff 15 ?? ?? ?? ?? 8b f0 3b f3}  //weight: 1, accuracy: Low
        $x_1_2 = {74 1e 53 ff 75 ?? ff 75 ?? 56 ff 75 ?? ff 15 ?? ?? ?? ?? 85 c0 74 ?? ff 75 08 03 fe ff d7 8b d8}  //weight: 1, accuracy: Low
        $x_1_3 = {8b 4c 24 0c 85 c9 74 ?? 0f b6 44 24 08 69 c0 01 01 01 01 8b d1 53 57 8b 7c 24 0c c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 5f}  //weight: 1, accuracy: Low
        $x_1_4 = {44 6c 6c 47 65 74 43 6c 61 73 73 4f 62 6a 65 63 74 [0-8] 70 6e 67 66 69 6c 74}  //weight: 1, accuracy: Low
        $x_2_5 = {70 6e 67 66 c7 45 ?? 69 6c 74 00 c7 45 ?? 44 6c 6c 47 c7 45 ?? 65 74 43 6c}  //weight: 2, accuracy: Low
        $x_1_6 = {3b de 74 23 8d 45 fc 50 6a 40 ff 75 10 57 ff 15 ?? ?? ?? ?? 85 c0 74 0f ff 75 08 03 df ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Lurk_A_2147662047_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lurk.gen!A"
        threat_id = "2147662047"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lurk"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 8b f0 6a 65 5f 83 fe 69 0f 85 ?? ?? ?? ?? 0f be 42 02 50 e8}  //weight: 1, accuracy: Low
        $x_1_2 = {32 14 0e 47 88 11 41 84 d2 75 e9 8b 45 08}  //weight: 1, accuracy: High
        $x_1_3 = {74 16 84 c9 75 21 80 78 fe 65 75 1b 80 78 fd 78 75 15 80 78 fc 65 75 0f}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Lurk_H_2147678655_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lurk.H"
        threat_id = "2147678655"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lurk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 4d fc 8d 41 ff eb 0b 80 bc 05 f8 fe ff ff 5c 74 07 48 3b c7 7f f1 eb 01}  //weight: 1, accuracy: High
        $x_1_2 = {69 63 6f 6e 00 00 00 00 7b 31 31 38 42 45 44 43 43 2d 41 39 30 31 2d 34 32 30 33 2d 42 34 46 32 2d 41 44 43 42 39 35 37 44 31 38 38 37 7d 00}  //weight: 1, accuracy: High
        $x_1_3 = {25 73 5c 25 73 2e 74 70 6d 00 00 00 25 55 73 65 72 50 72 6f 66 69 6c 65 25 00 00 00 25 54 4d 50 25 00}  //weight: 1, accuracy: High
        $x_1_4 = {34 32 79 75 39 64 00 00 70 73 61 61 77 32}  //weight: 1, accuracy: High
        $x_1_5 = {64 6b 6b 6a 2e 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_6 = "eElevation:Administrator!new:{" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_Win32_Lurk_I_2147693165_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lurk.I"
        threat_id = "2147693165"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lurk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 90 64 02 00 00 8b 45 f4 83 c0 40 50 8b 45 f4 ff 90 68 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {b8 aa aa aa aa 76 39 56 0f be 0a 83 c9 20 f6 c3 01 8b f0 75 0e c1 e6 07 33 ce 8b f0 c1 ee 03}  //weight: 1, accuracy: High
        $x_1_3 = {81 ff ce 01 06 5c 0f 84 ?? ?? ?? ?? be 2d 4f c3 66 3b fe}  //weight: 1, accuracy: Low
        $x_1_4 = "&aq=f&aqi=&aql=&oq=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanSpy_Win32_Lurk_J_2147693166_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Lurk.J"
        threat_id = "2147693166"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Lurk"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {ff 90 64 02 00 00 8b 45 f4 83 c0 40 50 8b 45 f4 ff 90 68 02 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {b8 aa aa aa aa 76 39 56 0f be 0a 83 c9 20 f6 c3 01 8b f0 75 0e c1 e6 07 33 ce 8b f0 c1 ee 03}  //weight: 1, accuracy: High
        $x_1_3 = {81 ff ce 01 06 5c 0f 84 ?? ?? ?? ?? be 2d 4f c3 66 3b fe}  //weight: 1, accuracy: Low
        $x_1_4 = "&aq=f&aqi=&aql=&oq=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

