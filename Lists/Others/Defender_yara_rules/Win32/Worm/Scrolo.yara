rule Worm_Win32_Scrolo_A_2147651905_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Scrolo.A"
        threat_id = "2147651905"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Scrolo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "27"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "NvCenter.lnk" ascii //weight: 5
        $x_5_2 = "WINDOWS\\system\\servise" ascii //weight: 5
        $x_5_3 = "WINDOWS\\system32\\deb.sys" ascii //weight: 5
        $x_1_4 = "ShowSuperHidden" ascii //weight: 1
        $x_1_5 = "HideFileExt" ascii //weight: 1
        $x_1_6 = "NoFolderOptions" ascii //weight: 1
        $x_1_7 = "DisableTaskMgr" ascii //weight: 1
        $x_10_8 = {6a 09 e8 25 d4 fe ff a8 01 74 13 68 05 00 04 00 6a 00 68 f0 97 41 00 e8 9c d4 fe ff}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

