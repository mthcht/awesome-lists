rule HackTool_Win32_Lsassdump_P_2147805372_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Lsassdump.P"
        threat_id = "2147805372"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Lsassdump"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "create a dump with a valid signature" ascii //weight: 1
        $x_1_2 = "the PID of LSASS" ascii //weight: 1
        $x_3_3 = "pypykatz lsa minidump" ascii //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

