rule TrojanDownloader_Win32_Vorloma_A_2147655282_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Vorloma.A"
        threat_id = "2147655282"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Vorloma"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "460"
        strings_accuracy = "High"
    strings:
        $x_200_1 = "dtoptool.com/pds/launcher/" ascii //weight: 200
        $x_200_2 = "C:\\Program Files\\NVIDIA.exe" ascii //weight: 200
        $x_20_3 = "guide.allblet.net/allblet.php" ascii //weight: 20
        $x_20_4 = "Launcher\\miniLauncher.exe" ascii //weight: 20
        $x_20_5 = "DelZip190.dll" ascii //weight: 20
        $x_30_6 = "dtoptool_v3" ascii //weight: 30
        $x_10_7 = "\\dtc\\datx" ascii //weight: 10
        $x_10_8 = "\\ut\\MiniLauncher.exe" ascii //weight: 10
        $x_10_9 = "\\WLauncher\\wLauncher.exe" ascii //weight: 10
        $x_5_10 = "Warcraft III.exe" ascii //weight: 5
        $x_5_11 = "Frozen Throne.exe" ascii //weight: 5
        $x_5_12 = "war3_original_run" ascii //weight: 5
        $x_5_13 = "lineage_test_run" ascii //weight: 5
        $x_5_14 = "wow_addon_delete" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_200_*) and 1 of ($x_20_*) and 2 of ($x_10_*) and 4 of ($x_5_*))) or
            ((2 of ($x_200_*) and 1 of ($x_20_*) and 3 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_200_*) and 2 of ($x_20_*) and 4 of ($x_5_*))) or
            ((2 of ($x_200_*) and 2 of ($x_20_*) and 1 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_200_*) and 2 of ($x_20_*) and 2 of ($x_10_*))) or
            ((2 of ($x_200_*) and 3 of ($x_20_*))) or
            ((2 of ($x_200_*) and 1 of ($x_30_*) and 1 of ($x_10_*) and 4 of ($x_5_*))) or
            ((2 of ($x_200_*) and 1 of ($x_30_*) and 2 of ($x_10_*) and 2 of ($x_5_*))) or
            ((2 of ($x_200_*) and 1 of ($x_30_*) and 3 of ($x_10_*))) or
            ((2 of ($x_200_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 2 of ($x_5_*))) or
            ((2 of ($x_200_*) and 1 of ($x_30_*) and 1 of ($x_20_*) and 1 of ($x_10_*))) or
            ((2 of ($x_200_*) and 1 of ($x_30_*) and 2 of ($x_20_*))) or
            (all of ($x*))
        )
}

