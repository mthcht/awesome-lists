rule TrojanDownloader_Win32_Tipikit_A_2147600520_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tipikit.A"
        threat_id = "2147600520"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tipikit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "tpktskend.php" ascii //weight: 1
        $x_1_2 = {63 3a 5c 63 6f 6e 66 [0-1] 2e 6d 79 00}  //weight: 1, accuracy: Low
        $x_1_3 = {5f 73 76 63 68 6f 73 74 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_4 = {49 6e 73 74 46 75 6e 00}  //weight: 1, accuracy: High
        $x_1_5 = "Urlmon.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tipikit_B_2147600524_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tipikit.B"
        threat_id = "2147600524"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tipikit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 41 75 07 e8 ?? ?? ff ff eb 33 e8 ?? ?? ff ff 83 3d ?? ?? 40 00 00 75 00 eb 1a 68 ?? ?? 00 00 07 00 66 81 3d ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tipikit_B_2147604727_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tipikit.gen!B"
        threat_id = "2147604727"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tipikit"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "90"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "SOFTWARE\\Borland\\Delphi\\RTL" ascii //weight: 10
        $x_10_2 = "FPUMaskValue" ascii //weight: 10
        $x_10_3 = "WriteFile" ascii //weight: 10
        $x_10_4 = "CreateFileA" ascii //weight: 10
        $x_10_5 = "CreateProcessA" ascii //weight: 10
        $x_10_6 = "URLDownloadToFileA" ascii //weight: 10
        $x_10_7 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" ascii //weight: 10
        $x_10_8 = "C:\\WINDOWS\\SYSTEM32KBRunOnce2.tm_" ascii //weight: 10
        $x_10_9 = {68 74 74 70 3a 2f 2f 6d 73 69 65 73 65 74 74 69 6e 67 73 2e 63 6f 6d 2f 63 68 65 63 6b 2f [0-16] 2e 70 68 70 3f 74 73 6b 3d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tipikit_C_2147604766_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tipikit.C"
        threat_id = "2147604766"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tipikit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2d 41 75 07 e8 ?? ?? ff ff eb 2a e8 ?? ?? ff ff eb 1a 68 60 ea 00 00 e8 ?? ?? 00 00 e8 07 00 66 81 3d ?? ?? 40 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Tipikit_D_2147708784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Tipikit.D"
        threat_id = "2147708784"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Tipikit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 ff 00 76 2a 6a 00 e8 ?? ?? ?? ?? 6a ?? 8d 45 f0 50 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 0b c0 75 0f e8 ?? ?? ?? ?? 24 0f fe c8 30 06 46 4f eb d1 8b 45 08 c9 c2 04 00}  //weight: 1, accuracy: Low
        $x_1_2 = {89 45 fc 6a 00 6a 00 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 6a 00 68 ?? ?? ?? ?? a1 ?? ?? ?? ?? ff d0 ff 75 fc 50 a1 ?? ?? ?? ?? ff d0 ff d0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

