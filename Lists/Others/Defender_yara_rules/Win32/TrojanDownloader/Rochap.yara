rule TrojanDownloader_Win32_Rochap_K_2147628586_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rochap.K"
        threat_id = "2147628586"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rochap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 fc 8a 5c 38 ff 80 e3 0f 8b 45 f4 8a 44 30 ff 24 0f 32 d8 80 f3 0a}  //weight: 1, accuracy: High
        $x_1_2 = {63 6f 6e 74 61 64 6f 72 2e 64 6c 6c 00 63 61 72 72 65 67 61 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rochap_P_2147636210_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rochap.P"
        threat_id = "2147636210"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rochap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 72 69 74 69 73 68 2e 64 6c 6c 00 62 65 73 74 6f 66 00}  //weight: 1, accuracy: High
        $x_1_2 = {8b 45 ec e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 89 45 fc ff 75 f8 ff 75 f4 ff 55 fc 33 c0}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rochap_R_2147651322_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rochap.R"
        threat_id = "2147651322"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rochap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {64 6c 6c 2e 64 6c 6c 00 72 6f 64 61 72}  //weight: 1, accuracy: High
        $x_1_2 = {89 45 fc ff 75 ?? ff 75 [0-14] ff 55 ?? 33 c0 5a 59 59 64 89 10}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Rochap_T_2147651801_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rochap.T"
        threat_id = "2147651801"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rochap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 83 d4 03 00 00 ff 70 08 68 ?? ?? ?? 00 8b 83 cc 03 00 00 ff 70 08 68 ?? ?? ?? 00 8b 83 d0 03 00 00 ff 70 08 68 ?? ?? ?? 00 8d 45 c4}  //weight: 1, accuracy: Low
        $x_1_2 = "TGhost1" ascii //weight: 1
        $x_1_3 = "TmrUACTimer" ascii //weight: 1
        $x_1_4 = "TmrDownTimer" ascii //weight: 1
        $x_1_5 = "opjtsfXuofssvD" ascii //weight: 1
        $x_1_6 = "ubutuppc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

