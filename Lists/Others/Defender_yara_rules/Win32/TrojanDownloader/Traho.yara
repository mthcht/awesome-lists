rule TrojanDownloader_Win32_Traho_A_2147610621_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Traho.A"
        threat_id = "2147610621"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Traho"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {00 68 74 74 70 3a 2f 2f 73 70 6f 72 74 73 2e 79 61 68 6f 6f 35 35 30 2e 63 6f 6d 2f 69 6d 61 67 65 2f 6c 6f 67 6f 2e 6a 70 67 3f 71 75 65 72 79 69 64 3d 38 30 ?? ?? ?? 00}  //weight: 10, accuracy: Low
        $x_1_2 = "\\tempaq" ascii //weight: 1
        $x_1_3 = {00 25 73 25 73 25 73 25 73 25 73 3f 71 75 65 72 79 69 64 3d 25 73 00}  //weight: 1, accuracy: High
        $x_1_4 = "HTTP/1.0" ascii //weight: 1
        $x_1_5 = "InternetOpenUrlA" ascii //weight: 1
        $x_1_6 = "InternetQueryDataAvailable" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

