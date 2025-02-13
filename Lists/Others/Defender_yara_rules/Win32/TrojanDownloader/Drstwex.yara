rule TrojanDownloader_Win32_Drstwex_A_2147644433_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drstwex.A"
        threat_id = "2147644433"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drstwex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 53 05 75 0d 00 00 81 e8 01 00 00 00 c1 e3 02}  //weight: 1, accuracy: High
        $x_1_2 = {50 53 05 75 0d 00 00 48 c1 e3 02}  //weight: 1, accuracy: High
        $x_5_3 = {90 90 8a 1e 90 90 90 32 d8 90 88 1e}  //weight: 5, accuracy: High
        $x_5_4 = "WaitForSingleObject" ascii //weight: 5
        $x_5_5 = "CreateThread" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Drstwex_A_2147644433_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drstwex.A"
        threat_id = "2147644433"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drstwex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 4d 0c 8b 55 08 e8 0b 00 00 00 30 02 42 e2 f6}  //weight: 1, accuracy: High
        $x_1_2 = {83 f8 00 0f 85 f8 00 00 00 6a 00 6a ?? 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8}  //weight: 1, accuracy: Low
        $x_1_3 = {68 52 02 00 00 e8 ?? ?? ?? ?? a3 ?? ?? ?? ?? 05 ff 00 00 00 a3 ?? ?? ?? ?? 05 ff 00 00 00 a3 ?? ?? ?? ?? 83 c0 44}  //weight: 1, accuracy: Low
        $x_1_4 = {8b 44 24 10 [0-5] c7 00 c3 ?? ?? ?? b8 00 00 00 00 c3}  //weight: 1, accuracy: Low
        $x_1_5 = {8b 00 8b d0 c1 e0 03 33 c2 05 ?? ?? ?? ?? 5a 89 02 c1 e8 18 5a c3}  //weight: 1, accuracy: Low
        $x_1_6 = {6a 00 6a 07 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 ?? 50 8d 45 ?? 50 ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8b 7d ?? 8b 07}  //weight: 1, accuracy: Low
        $x_1_7 = {50 6a 07 68 ?? ?? ?? ?? ff 35 ?? ?? ?? ?? e8 ?? ?? ?? ?? 8d 45 f8 50 8d 45 fc 50}  //weight: 1, accuracy: Low
        $x_1_8 = {89 45 fc 6a 00 68 00 04 00 00 ff 75 fc ff 75 08 e8 ?? ?? ?? ?? 83 f8 00 74 59 83 f8 ff 74 4b 89 45 f8 03 45 f0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Drstwex_C_2147646028_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drstwex.C"
        threat_id = "2147646028"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drstwex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {50 8b f8 8b 4d f0 83 f9 00 74 ?? 8b 75 f4 f3 a4 8b 4d f8 8b 75 fc f3 a4 8b 45 f0 03 45 f8 89 45 f0 68 00 80 00 00 6a 00 ff 75 f4}  //weight: 1, accuracy: Low
        $x_1_2 = {50 8b 00 8b d0 c1 e0 02 33 c2 05 85 00 00 00 5a 89 02 c1 e8 18 5a c3}  //weight: 1, accuracy: High
        $x_1_3 = {83 f8 00 0f 85 ?? ?? ?? ?? 6a 00 6a 07 68 08 09 10 00 ff 35 ?? ?? ?? ?? e8 27 ff ff ff 8d 45 f8 50 8d 45 fc 50}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Drstwex_E_2147647716_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drstwex.E"
        threat_id = "2147647716"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drstwex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {50 8b 00 8b d0 c1 e0 03 33 c2 05 bd 04 00 00 5a 89 02 c1 e8 18 5a c3}  //weight: 1, accuracy: High
        $x_1_2 = "4ere" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Drstwex_F_2147650767_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drstwex.F"
        threat_id = "2147650767"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drstwex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "a32sdfherty" ascii //weight: 1
        $x_1_2 = {8b 00 8b d0 c1 e0 03 33 c2 05 bd 04 00 00 5a 89 02 c1 e8 18}  //weight: 1, accuracy: High
        $x_1_3 = {8a 1e 32 d8 88 1e eb df}  //weight: 1, accuracy: High
        $x_1_4 = {8b 4d 0c 8b 55 08 e8 0b 00 00 00 30 02 42 e2 f6}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Drstwex_H_2147651609_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drstwex.H"
        threat_id = "2147651609"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drstwex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rewdsfer2" ascii //weight: 1
        $x_1_2 = {58 e2 da e9 ?? ?? ?? ?? 59 5e a1 ?? ?? ?? ?? 8a 1e 32 d8 88 1e eb dc}  //weight: 1, accuracy: Low
        $x_1_3 = {83 e0 fd 33 c1 05 bd 04 00 00 a3 ?? ?? ?? ?? c1 c8 10 eb (0f|0e)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule TrojanDownloader_Win32_Drstwex_I_2147652563_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Drstwex.I"
        threat_id = "2147652563"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Drstwex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 18 5b 58 e2 bd e9 b3 f0 ff ff 59 5e a1 79 0d 16 00 90 8a 1e 90 32 d8 90 88 1e 90 eb d2}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

