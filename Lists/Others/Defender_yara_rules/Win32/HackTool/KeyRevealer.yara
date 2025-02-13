rule HackTool_Win32_KeyRevealer_2147690634_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/KeyRevealer"
        threat_id = "2147690634"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyRevealer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CryptGenKey" ascii //weight: 1
        $x_1_2 = "CryptExportKey" ascii //weight: 1
        $x_1_3 = "\\Program Files\\rkfree\\rkfree.exe" ascii //weight: 1
        $x_1_4 = "Revealer Keylogger Free" ascii //weight: 1
        $x_1_5 = "rvlkl\\cfg\\cfg" ascii //weight: 1
        $x_1_6 = "RVLKLSetupFileMapping" ascii //weight: 1
        $x_1_7 = "SeTakeOwnershipPrivilege" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

