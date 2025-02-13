rule TrojanDownloader_Win32_Vividi_A_2147651843_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vividi.A"
        threat_id = "2147651843"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vividi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4e 8b 45 dc 80 7c 30 ff 2f 75 ?? 8d 85 48 fe ff ff 50 68 01 01 00 00 e8 ?? ?? ?? ?? 6a 00 6a 01 6a 02 e8 ?? ?? ?? ?? 8b f0 66 c7 85 38 fe ff ff 02 00 83 ff 01 7c ?? 81 ff ff ff 00 00 7e ?? bf 50 00 00 00}  //weight: 3, accuracy: Low
        $x_1_2 = {2e 69 6e 66 6f 2f ?? 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "C:\\TEMP\\1.exe" ascii //weight: 1
        $x_1_4 = "120.125.201.101" ascii //weight: 1
        $x_1_5 = "GET /1.exe HTTP/1.1" ascii //weight: 1
        $x_1_6 = "Accept-Language: en-us;q=0.5" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

