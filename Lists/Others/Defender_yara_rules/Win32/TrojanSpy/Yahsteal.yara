rule TrojanSpy_Win32_Yahsteal_C_2147641975_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Yahsteal.C"
        threat_id = "2147641975"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Yahsteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "RUNDLL32.EXE C:\\Windows\\iexplore.exe,i" ascii //weight: 4
        $x_2_2 = "%s/mm%s.LOG" ascii //weight: 2
        $x_2_3 = "%s/pp%s.LOG" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

