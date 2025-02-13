rule TrojanDownloader_Win32_Dogkild_E_2147552812_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogkild.E"
        threat_id = "2147552812"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "if exist \"%s\" goto Repeat" ascii //weight: 1
        $x_1_2 = "pcidump" ascii //weight: 1
        $x_1_3 = "\\\\.\\pcidump" ascii //weight: 1
        $x_1_4 = "update~.exe" ascii //weight: 1
        $x_1_5 = "\\rundll32.exe" ascii //weight: 1
        $x_1_6 = "_uok.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dogkild_D_2147623986_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogkild.D"
        threat_id = "2147623986"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "OpenSCManagerA" ascii //weight: 1
        $x_1_2 = {70 63 69 64 75 6d 70 00 5c 5c 2e 5c 70 63 69 64 75 6d 70}  //weight: 1, accuracy: High
        $x_1_3 = {43 4f 4d 53 50 45 43 00 73 63 76 68 6f 73 74 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_4 = {53 45 52 56 45 52 00 00 5c 6b 69 6c 6c 64 6c 6c 2e 64 6c 6c}  //weight: 1, accuracy: High
        $x_1_5 = {e9 01 00 00 00 e8 b8 11 06 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dogkild_A_2147624245_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogkild.A"
        threat_id = "2147624245"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\\\.\\pcidump" ascii //weight: 1
        $x_1_2 = "killdll.dll" ascii //weight: 1
        $x_1_3 = {6a 08 8d 45 f0 50 68 14 20 22 00 8b 4d f8 51 ff 15 ?? ?? ?? ?? 89 45 fc eb 07 c7 45 fc ff ff ff ff}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dogkild_K_2147625414_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogkild.K"
        threat_id = "2147625414"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 4b e1 22 00 (ff|50) ff 15 ?? ?? ?? ?? 85 c0 74}  //weight: 1, accuracy: Low
        $x_1_2 = {83 c0 04 89 ?? 83 c0 14 89 ?? 66 81 38 0b 01 75 ?? 8b 4c 24 10 05 e0 00 00 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6b 69 6c 6c 64 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = {5c 5c 2e 5c 4b 49 4c 4c 50 53 5f 44 72 76 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dogkild_N_2147626543_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogkild.N"
        threat_id = "2147626543"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 45 ec 50 ff 15 ?? ?? ?? ?? 66 81 7d ec d7 07 0f 86 d0 00 00 00 be 04 01 00 00 8d 85 e8 fe ff ff 56 50 ff 15 ?? ?? ?? ?? 8d 85 e8 fe ff ff 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 8d 85 e8 fe ff ff 68 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 83 c4 10 66 81 7d ec d8 07 76 16 8d 85 e8 fe ff ff}  //weight: 1, accuracy: Low
        $x_1_2 = {33 db 53 68 80 00 00 00 6a 03 53 53 68 00 00 00 c0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 83 f8 ff 89 45 fc 74 23}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dogkild_R_2147628795_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogkild.R"
        threat_id = "2147628795"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {7e 0e fe 8e ?? ?? ?? ?? 57 46 ff d3 3b f0 7c f2}  //weight: 1, accuracy: Low
        $x_1_2 = {68 4b e1 22 00 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 74 0f}  //weight: 1, accuracy: Low
        $x_1_3 = {83 ce ff c6 45 ?? 5c c6 45 ?? 5c c6 45 ?? 2e c6 45 ?? 5c c6 45 ?? 6d c6 45 ?? 73 c6 45 ?? 63 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 69 c6 45 ?? 66 c6 45 ?? 67}  //weight: 1, accuracy: Low
        $x_1_4 = {53 50 c6 45 ?? 63 c6 45 ?? 6f c6 45 ?? 6e c6 45 ?? 66 c6 45 ?? 69 c6 45 ?? 67 c6 45 ?? 20 c6 45 ?? 61 c6 45 ?? 76 c6 45 ?? 70}  //weight: 1, accuracy: Low
        $x_1_5 = {88 45 0b 8d 45 f8 50 8d 45 0b 6a 01 50 ff 75 fc ff 15 ?? ?? ?? ?? ff 75 10 46 57 ff 15 ?? ?? ?? ?? 3b f0 72 d4}  //weight: 1, accuracy: Low
        $x_1_6 = {8b f0 c1 ee 19 c1 e0 07 0b f0 0f be c1 8a 4a 01 33 c6 42 84 c9 75 e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanDownloader_Win32_Dogkild_S_2147629349_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogkild.S"
        threat_id = "2147629349"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6a 04 51 68 18 00 22 00 56 c7 45 f4 e8 03 00 00}  //weight: 1, accuracy: High
        $x_1_2 = {75 00 8d 4c 24 0c 6a 00 51 68 80 20 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Dogkild_V_2147630833_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogkild.V"
        threat_id = "2147630833"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 19 56 8b f0 c1 ee 19 c1 e0 07 0b f0 0f be c1 8a 4a 01 33 c6 42 84 c9 75 e9}  //weight: 1, accuracy: High
        $x_2_2 = {6a 01 ff 55 f0 68 29 1c a8 58 6a 02 e8 ?? ?? ?? ?? 89 45 ec 6a 00 6a 00 6a 10 ff 75 f8 ff 55 ec}  //weight: 2, accuracy: Low
        $x_1_3 = {e9 03 00 00 00 ef 90 90 03 c1 0f b6 c2 8b d0 0f c0 d4 92 69 d0 ae d0 c5 dd}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Dogkild_W_2147644713_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dogkild.W"
        threat_id = "2147644713"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dogkild"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\windows\\currentversion\\run" ascii //weight: 1
        $x_1_2 = "RunmeAtStartup" ascii //weight: 1
        $x_1_3 = "?uid=%s&address=%s&p=%d&a=%d" ascii //weight: 1
        $x_1_4 = "http://fu.o3sb.com:9999/img.jpg" ascii //weight: 1
        $x_1_5 = {68 74 74 70 3a 2f 2f [0-32] 3a ?? ?? ?? ?? 2f [0-8] 2f 72 6b 32 33 2e 65 78 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

