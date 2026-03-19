rule HackTool_Win32_MessenPass_2147670747_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/MessenPass"
        threat_id = "2147670747"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "MessenPass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "\\mspass\\command-line\\mspass.pdb" ascii //weight: 2
        $x_1_2 = "Software\\NirSoft\\MessenPass" ascii //weight: 1
        $x_1_3 = ".aim.session.password" ascii //weight: 1
        $x_1_4 = "stabular" ascii //weight: 1
        $x_1_5 = "skeepasst" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

