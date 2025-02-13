rule TrojanDownloader_Win32_Mapanna_2147603434_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Mapanna"
        threat_id = "2147603434"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Mapanna"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NOTEPAD.EXE %1" wide //weight: 1
        $x_1_2 = "QFSLKeylog.ini" wide //weight: 1
        $x_1_3 = "IExplorer.dll                                                              .dbt" wide //weight: 1
        $x_1_4 = "HKEY_CLASSES_ROOT\\DBTFILE\\shell\\open\\command\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

