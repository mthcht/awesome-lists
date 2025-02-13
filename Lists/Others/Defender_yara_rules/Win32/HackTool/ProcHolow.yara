rule HackTool_Win32_ProcHolow_BA_2147901534_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ProcHolow.BA"
        threat_id = "2147901534"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcHolow"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 6f 6c 6c 6f 77 47 68 6f 73 74 [0-15] 2e 4d 6f 64 75 6c 65 73 2e 45 76 61 73 69 6f 6e}  //weight: 1, accuracy: Low
        $x_1_2 = "ZwQueryInformationProcess" ascii //weight: 1
        $x_1_3 = "ReadProcessMemory" ascii //weight: 1
        $x_1_4 = "WriteProcessMemory" ascii //weight: 1
        $x_1_5 = "ResumeThread" ascii //weight: 1
        $x_1_6 = "CreateProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

