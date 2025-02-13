rule TrojanDownloader_Win32_Cavitate_C_2147598058_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cavitate.gen!C"
        threat_id = "2147598058"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cavitate"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b c8 81 e1 0f 00 00 80 79 05 49 83 c9 f0 41 8a 91 ?? ?? ?? 10 8a (88|98) ?? ?? ?? 10 32 (ca|da) 88 (88|98) ?? ?? ?? 10 40 3d ?? ?? 00 00 7c d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cavitate_D_2147599753_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cavitate.gen!D"
        threat_id = "2147599753"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cavitate"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8d 1c c5 00 00 00 00 2b d8 c1 e3 04 8d 44 03 81 8a 1c 0e 25 ff 00 00 00 32 d8 88 19 41 4f 75 e0 5f c6 04 2a 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cavitate_E_2147610328_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cavitate.gen!E"
        threat_id = "2147610328"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cavitate"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {81 c2 14 0c 00 00 0f af c2 25 ff ff 00 00 89 45 14 5a 8a 14 0e 8a 45 14 32 d0 8b 45 0c 88 11 41 48}  //weight: 1, accuracy: High
        $x_1_2 = {8d 8c 40 29 87 00 00 8a 04 16 81 e1 ff ff 01 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Cavitate_F_2147610416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Cavitate.gen!F"
        threat_id = "2147610416"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Cavitate"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 c3 60 0f af c3 25 ff ff 00 00 89 45 14 8a 04 0a 8a 5d 14 32 c3 88 01 8b 45 0c 41 48}  //weight: 1, accuracy: High
        $x_1_2 = {8b 6c 24 0c 83 fd 01 73 04 33 c0 5d c3 83 fd 05 76 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

