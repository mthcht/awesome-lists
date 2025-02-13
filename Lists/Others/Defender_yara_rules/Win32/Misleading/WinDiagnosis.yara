rule Misleading_Win32_WinDiagnosis_200095_0
{
    meta:
        author = "defender2yara"
        detection_name = "Misleading:Win32/WinDiagnosis"
        threat_id = "200095"
        type = "Misleading"
        platform = "Win32: Windows 32-bit platform"
        family = "WinDiagnosis"
        severity = "Low"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "runjkdefrag" ascii //weight: 1
        $x_1_2 = "stopjkdefrag" ascii //weight: 1
        $x_1_3 = "avast" ascii //weight: 1
        $x_2_4 = "alertdialog" ascii //weight: 2
        $x_10_5 = "fetchDataIssues@filesystem@opti" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

