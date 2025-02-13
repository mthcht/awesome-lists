rule TrojanDownloader_Win32_Rescoms_B_2147725996_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Rescoms.B"
        threat_id = "2147725996"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Rescoms"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "http://unifscon.com/RemAp.exe" wide //weight: 3
        $x_1_2 = "urldownloadtofilew" ascii //weight: 1
        $x_1_3 = "shellexecutew" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

