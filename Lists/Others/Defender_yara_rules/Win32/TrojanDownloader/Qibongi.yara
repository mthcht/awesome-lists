rule TrojanDownloader_Win32_Qibongi_A_2147618351_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Qibongi.A"
        threat_id = "2147618351"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Qibongi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 74 74 70 3a 00 78 6d 6c 77 69 6e 64 61 74 61 00 72 65 67 73 76 72 33 32 00 2f 73 20 00 43 3a 5c 57 49 4e 44 4f 57 53 5c 73 79 73 74 65 6d 33 32 5c [0-10] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_2 = "Debugger" ascii //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\iexplore.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Qibongi_B_2147618628_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Qibongi.B"
        threat_id = "2147618628"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Qibongi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 65 62 75 67 67 65 72 00 00 53 4f 46 54 57 41 52 45 5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 20 4e 54 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 49 6d 61 67 65 20 46 69 6c 65 20 45 78 65 63 75 74 69 6f 6e 20 4f 70 74 69 6f 6e 73 5c 69 65 78 70 6c 6f 72 65 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_2 = {68 74 74 70 3a 00 78 6d 6c 77 69 6e 64 61 74 61 00 72 65 67 73 76 72 33 32 [0-2] 2f 73 [0-4] 3a 5c 57 49 4e 44 4f 57 53 [0-3] 5c 73 79 73 74 65 6d 33 32 5c [0-10] 2e 64 6c 6c}  //weight: 1, accuracy: Low
        $x_1_3 = {6a 00 68 3f 00 0f 00 6a 00 6a 00 6a 00 68 ?? ?? ?? 00 68 02 00 00 80 e8 ?? 00 00 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

