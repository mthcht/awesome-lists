rule VirTool_Win32_Bofprochandle_A_2147901306_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Bofprochandle.A"
        threat_id = "2147901306"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Bofprochandle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bofstop" ascii //weight: 1
        $x_1_2 = "allocate handle" ascii //weight: 1
        $x_1_3 = "reallocate handle" ascii //weight: 1
        $x_1_4 = "duplicate handle" ascii //weight: 1
        $x_1_5 = "Failed to allocate objectNameInfo" ascii //weight: 1
        $x_1_6 = "killit failed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

