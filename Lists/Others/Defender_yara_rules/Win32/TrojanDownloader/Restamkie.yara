rule TrojanDownloader_Win32_Restamkie_A_2147706947_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Restamkie.A"
        threat_id = "2147706947"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Restamkie"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {00 74 74 70 73 3a 2f 2f 73 74 6f 72 61 67 65 2e 67 6f 6f 67 6c 65 61 70 69 73 2e 63 6f 6d 2f 63 6f 6e 76 69 74 65 2d 32 30 31 35 2f [0-16] 2e 7a 69 70}  //weight: 1, accuracy: Low
        $x_1_2 = "Runningames.exe" ascii //weight: 1
        $x_1_3 = "\\aK31MASTER02.exe" ascii //weight: 1
        $x_1_4 = "\\toys.dat" ascii //weight: 1
        $x_1_5 = {3b 04 24 5a 58 74 ?? 33 c0 55 68 ?? ?? ?? ?? 64 ff 30 64 89 20 68 ?? ?? ?? ?? 8b 45 f8 50 e8 ?? ?? ?? ?? 8b f0 89 f3 85 f6 74 ?? 6a 00 6a 00 8b 45 f4 e8 ?? ?? ?? ?? 50 8b 45 fc e8 ?? ?? ?? ?? 50 6a 00 ff d3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

