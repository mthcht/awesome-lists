rule TrojanDownloader_Win32_Complan_2147575172_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Complan"
        threat_id = "2147575172"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Complan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "http://www.comedy-planet.com/download/network" ascii //weight: 2
        $x_1_2 = "c%d.exe" ascii //weight: 1
        $x_1_3 = ".php?n=%d" ascii //weight: 1
        $x_1_4 = "\\cp.exe" ascii //weight: 1
        $x_1_5 = "GetSystemDirectoryA" ascii //weight: 1
        $x_1_6 = "ShellExecuteA" ascii //weight: 1
        $x_1_7 = "URLDownloadToFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

