rule VirTool_Win32_SuspNetstatExec_A_2147957142_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspNetstatExec.A"
        threat_id = "2147957142"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspNetstatExec"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cmd.exe" wide //weight: 1
        $x_1_2 = " /c " wide //weight: 1
        $x_1_3 = " set " wide //weight: 1
        $x_1_4 = " -s -p UDP" wide //weight: 1
        $x_1_5 = "=st&&" wide //weight: 1
        $x_1_6 = "=net&&" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

