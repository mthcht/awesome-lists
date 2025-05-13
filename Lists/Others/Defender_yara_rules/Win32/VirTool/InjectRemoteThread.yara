rule VirTool_Win32_InjectRemoteThread_NP_2147941199_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/InjectRemoteThread.NP"
        threat_id = "2147941199"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "InjectRemoteThread"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\phonehome.dll" ascii //weight: 1
        $x_1_2 = "\\temp\\sb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

