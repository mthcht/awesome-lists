rule HackTool_Win32_WinPswDump_A_2147777325_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/WinPswDump.A!dha"
        threat_id = "2147777325"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "WinPswDump"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lsass.exe" ascii //weight: 1
        $x_1_2 = "[x] Error: Could not open handle to lsass process" ascii //weight: 1
        $x_1_3 = "[x] Error: Could not find all DLL's in LSASS" ascii //weight: 1
        $x_1_4 = "[x] Error: Could not find credentials in lsass" ascii //weight: 1
        $x_1_5 = "get_lsass_exe\\x64\\Release\\GetWinPsw.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

