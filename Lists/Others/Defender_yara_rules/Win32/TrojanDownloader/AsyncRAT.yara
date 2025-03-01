rule TrojanDownloader_Win32_AsyncRAT_A_2147836646_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRAT.A!MTB"
        threat_id = "2147836646"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {81 ec 10 01 00 00 56 68 00 01 00 00 ff 15 18 ?? 40 00 50 ff 15 14 ?? 40 00 6a 0f ff 15 10 ?? 40 00 50 ff 15 ?? ?? 40 00 8b 35 ?? ?? 40 00 6a 00 ff d6 8b 00 50 6a 01 6a 04 ff 15 ?? ?? 40 00 ff d6 8b 08 8d 54 24 04 51 68 54 ?? 40 00 52 ff 15 ?? ?? 40 00 83 c4 0c 8d 44 24 04 6a 00 6a 00 50 68 4c ?? 40 00 68 44 ?? 40 00 6a 00 ff 15 ?? ?? 40 00 6a 00 ff 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_AsyncRAT_D_2147896748_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRAT.D!MTB"
        threat_id = "2147896748"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8a 85 67 ff ff ff 04 01 88 85 67 ff ff ff 0f be 85 67 ff ff ff 83 f8 5a 0f ?? ?? ?? ?? ?? 0f be 85 67 ff ff ff 50 68 ?? ad 42 00 8d 4d c8 51 e8 ?? ?? ?? ?? 83 c4 0c 6a 00 8d 45 c8 50 e8 ?? ?? ?? ?? 83 c4 08 89 45 bc 83 7d bc 00 0f ?? ?? ?? ?? ?? 8b 45 a4 83 c0 01 89 45 a4 8d 45 c8 50 68}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_AsyncRAT_E_2147897745_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRAT.E!MTB"
        threat_id = "2147897745"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "C:\\windows\\temp\\Client1.bin" ascii //weight: 2
        $x_2_2 = "File Downloader" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_AsyncRAT_F_2147899231_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/AsyncRAT.F!MTB"
        threat_id = "2147899231"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "AsyncRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {fe ff ff 28 01 00 00 68 24 01 00 00 6a 00 8d 85 ?? fe ff ff 50 e8 ?? ?? 00 00 83 c4 0c 83 a5 ?? fe ff ff 00 8d 85 ?? fe ff ff 50 ff b5 ?? fe ff ff e8 ?? ?? 00 00 89 85 ?? fe ff ff eb ?? 8d ?? ?? fe ff ff 50 ff b5 ?? fe ff ff e8 ?? ?? 00 00 89 85 ?? fe ff ff 83 bd ?? fe ff ff}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

