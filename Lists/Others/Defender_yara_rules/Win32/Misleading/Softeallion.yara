rule Misleading_Win32_Softeallion_240809_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/Softeallion"
        threat_id = "240809"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "Softeallion"
        severity = "25"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "E:\\wisefixer\\svn" ascii //weight: 1
        $x_1_2 = "MUTEX_WISE_FIXER_EXCLUDE_OBJECT_LUCK" wide //weight: 1
        $x_1_3 = "IDS_START_SCAN_RESULT_TAB_JUNKFILE" wide //weight: 1
        $x_1_4 = "ScanJunkFileErrorCount" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

