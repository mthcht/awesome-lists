rule TrojanDownloader_Win32_Ogimant_2147688526_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Ogimant"
        threat_id = "2147688526"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Ogimant"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "24"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "minimal_ware" ascii //weight: 2
        $x_2_2 = "8.8.8.8" ascii //weight: 2
        $x_2_3 = "MiniMalware" ascii //weight: 2
        $x_2_4 = "bla bla bla" ascii //weight: 2
        $x_2_5 = "created_and_modified.txt" ascii //weight: 2
        $x_2_6 = "created_and_deleted.txt" ascii //weight: 2
        $x_2_7 = "created.txt" ascii //weight: 2
        $x_2_8 = "created_and_rename.txt" ascii //weight: 2
        $x_2_9 = "after_rename_file.txt" ascii //weight: 2
        $x_2_10 = "created_and_rename2.txt" ascii //weight: 2
        $x_2_11 = "created_and_moved.txt" ascii //weight: 2
        $x_2_12 = "after_move_file.txt" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

