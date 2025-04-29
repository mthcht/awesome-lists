rule VirTool_Win32_SuspPowerShellCmd_A_2147910917_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowerShellCmd.A"
        threat_id = "2147910917"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowerShellCmd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell.exe" ascii //weight: 1
        $x_1_2 = " bypass" ascii //weight: 1
        $x_1_3 = {20 00 2d 00 46 00 69 00 6c 00 65 00 20 00 [0-16] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 45 00 4d 00 50 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_4 = {20 2d 46 69 6c 65 20 [0-16] 5c 57 69 6e 64 6f 77 73 5c 54 45 4d 50 5c}  //weight: 1, accuracy: Low
        $x_1_5 = {20 00 2d 00 45 00 72 00 72 00 6f 00 72 00 4c 00 6f 00 67 00 46 00 69 00 6c 00 65 00 20 00 [0-16] 5c 00 57 00 69 00 6e 00 64 00 6f 00 77 00 73 00 5c 00 54 00 45 00 4d 00 50 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_6 = {20 2d 45 72 72 6f 72 4c 6f 67 46 69 6c 65 20 [0-16] 5c 57 69 6e 64 6f 77 73 5c 54 45 4d 50 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule VirTool_Win32_SuspPowerShellCmd_BL_2147939802_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowerShellCmd.BL"
        threat_id = "2147939802"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowerShellCmd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "& c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe" ascii //weight: 3
        $x_3_2 = "-exec bypass -command " ascii //weight: 3
        $x_3_3 = "set-psreadlineoption" ascii //weight: 3
        $x_1_4 = "-historysavestyle savenothing" ascii //weight: 1
        $x_1_5 = "-historysavepath ${temp}/" ascii //weight: 1
        $x_1_6 = "-maximumhistorycount 1" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_3_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_Win32_SuspPowerShellCmd_BA_2147940318_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspPowerShellCmd.BA"
        threat_id = "2147940318"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspPowerShellCmd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "& c:\\windows\\system32\\windowspowershell\\v1.0\\powershell.exe" ascii //weight: 1
        $x_1_2 = "-exec bypass -command " ascii //weight: 1
        $x_1_3 = "IO.FileStream '\\\\.\\C:'" ascii //weight: 1
        $x_1_4 = "'Open', 'Read', 'ReadWrite'" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

