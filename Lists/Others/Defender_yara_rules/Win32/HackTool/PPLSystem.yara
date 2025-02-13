rule HackTool_Win32_PPLSystem_A_2147912207_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PPLSystem.A"
        threat_id = "2147912207"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PPLSystem"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "library\\core\\src\\escape.rs" ascii //weight: 1
        $x_1_2 = "sys\\sync\\rwlock\\futex.rs" ascii //weight: 1
        $x_1_3 = "pidArgsDLLPath of the (unsigned) DLL to injectDUMPWhere to write the" ascii //weight: 1
        $x_1_4 = "livedump on disk (must be a full path)PIDTarget PID to inject" ascii //weight: 1
        $x_1_5 = "Remote COM secret" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

