rule HackTool_Win32_SuspMsxslExec_A_2147967376_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/SuspMsxslExec.A"
        threat_id = "2147967376"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspMsxslExec"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "msxsl" wide //weight: 1
        $x_1_2 = "cmd.exe" wide //weight: 1
        $x_1_3 = "powershell.exe" wide //weight: 1
        $x_1_4 = "pwsh.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

