rule TrojanDownloader_Win32_Mutaudan_SA_2147781180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mutaudan.SA!MTB"
        threat_id = "2147781180"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mutaudan"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\info-1.txt" wide //weight: 1
        $x_1_2 = "download_quiet" wide //weight: 1
        $x_1_3 = "\\Valorant+Cheat+Pack-RTMD-AKV7WGDGzgQAvhwCAERFFwASAFR1bVUA.exe" wide //weight: 1
        $x_1_4 = "C:\\Program Files\\Autumn-Dawn" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

