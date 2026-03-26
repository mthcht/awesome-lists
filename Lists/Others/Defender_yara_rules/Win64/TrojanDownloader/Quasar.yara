rule TrojanDownloader_Win64_Quasar_PAHS_2147965699_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win64/Quasar.PAHS!MTB"
        threat_id = "2147965699"
        type = "TrojanDownloader"
        platform = "Win64: Windows 64-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "powershell -WindowStyle Hidden -Command \"(New-Object Net.WebClient).DownloadFile" ascii //weight: 2
        $x_2_2 = "powershell.exe -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command" ascii //weight: 2
        $x_1_3 = "SOFTWARE\\Microsoft\\TrashCode\\FakeKey" ascii //weight: 1
        $x_1_4 = "runas" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

