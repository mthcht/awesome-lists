rule TrojanSpy_Win32_Banguplin_A_2147706036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Banguplin.A"
        threat_id = "2147706036"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Banguplin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "48E8778EA65681B54EF812B121D6659251399F40E0" wide //weight: 2
        $x_2_2 = "B5AC22C57AA95B84AD8EE667E11BD00538EC" wide //weight: 2
        $x_1_3 = "AEA72ECE6796B89C8AB111B81020" wide //weight: 1
        $x_1_4 = "F065F739CF73A15E" wide //weight: 1
        $x_1_5 = "A75D86A55E89B09AAB5BF2" wide //weight: 1
        $x_1_6 = "312A55F612222A37D0" wide //weight: 1
        $x_1_7 = "1CD10D25DB016C945483" wide //weight: 1
        $x_1_8 = "6F90EA68F878" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

