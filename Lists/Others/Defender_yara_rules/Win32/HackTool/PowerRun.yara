rule HackTool_Win32_PowerRun_A_2147827460_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PowerRun.A"
        threat_id = "2147827460"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerRun"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PowerRun has been created to run Applications with Elevated Privileges" ascii //weight: 1
        $x_1_2 = "Sordum" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

