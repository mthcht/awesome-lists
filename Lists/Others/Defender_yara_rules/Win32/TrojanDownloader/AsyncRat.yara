rule TrojanDownloader_Win32_AsyncRat_CCHB_2147901225_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRat.CCHB!MTB"
        threat_id = "2147901225"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {83 c4 08 eb ?? c7 45 e0 ?? ?? ?? ?? c7 45 e4 ?? ?? ?? ?? 8b 55 e4 52 8b 45 e0 50 e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_AsyncRat_CCHD_2147901416_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRat.CCHD!MTB"
        threat_id = "2147901416"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b f8 ff 15 ?? ?? ?? ?? ff d6 2b c7 2d ?? ?? ?? ?? 99 8b fa 8b f0 57 56 68 ?? ?? ?? ?? e8 ?? ?? ?? ?? 33 f7 2b f7 83 c4 0c 83 fe 64 7e 14 68}  //weight: 1, accuracy: Low
        $x_1_2 = "sandbox!!!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_AsyncRat_CCIQ_2147913736_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRat.CCIQ!MTB"
        threat_id = "2147913736"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 55 fc 8a 04 82 30 01 8b 4d f8 8b 46 04 41 2b 06 89 4d f8 3b c8 72}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_AsyncRat_CCJB_2147915088_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRat.CCJB!MTB"
        threat_id = "2147915088"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 16 8b 49 0c 8b 42 0c 8b 55 a4 8a 04 10 8b 55 d4 32 04 1a 8b 55 a0 88 04 11 8b 45 e8 83 c0 01 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_AsyncRat_G_2147917857_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRat.G!MTB"
        threat_id = "2147917857"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 4c 05 c9 32 ca 88 88 ?? ?? ?? ?? 40 83 f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_AsyncRat_PA_2147943541_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRat.PA!MTB"
        threat_id = "2147943541"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Start-Process" wide //weight: 1
        $x_4_2 = {74 00 70 00 3a 00 2f 00 2f 00 67 00 65 00 74 00 73 00 76 00 65 00 72 00 69 00 66 00 66 00 2e 00 63 00 6f 00 6d 00 2f 00 72 00 76 00 78 00 6c 00 67 00 68 00 37 00 2f 00 [0-21] 2e 00 65 00 78 00 65 00}  //weight: 4, accuracy: Low
        $x_1_3 = "/C powershell -Command \"Invoke-WebRequest -Uri" wide //weight: 1
        $x_1_4 = "/C powershell -Command \"Add-MpPreference -ExclusionPath" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

