rule TrojanDownloader_Win32_TwinCarbon_A_2147925253_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/TwinCarbon.A!dha"
        threat_id = "2147925253"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "TwinCarbon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "File downloaded successfully: " ascii //weight: 1
        $x_1_2 = "The file is a PNG image." ascii //weight: 1
        $x_1_3 = ", DoUpdateInstanceEx" ascii //weight: 1
        $x_1_4 = "Failed to call the DLL function." ascii //weight: 1
        $x_1_5 = "Failed to open output file." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

