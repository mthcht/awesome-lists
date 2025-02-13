rule Virus_Win32_Belarus_A_2147721289_0
{
    meta:
        author = "defender2yara"
        detection_name = "Virus:Win32/Belarus.A!bit"
        threat_id = "2147721289"
        type = "Virus"
        platform = "Win32: Windows 32-bit platform"
        family = "Belarus"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "BELARUS-VIRUS-MAKER" ascii //weight: 3
        $x_1_2 = "Explorer.exe smrss.exe" ascii //weight: 1
        $x_1_3 = "C:\\WINDOWS\\svchost.exe" ascii //weight: 1
        $x_1_4 = "C:\\WINDOWS\\system32\\freizer.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

