rule HackTool_Win32_Vncpwdump_2147694235_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Vncpwdump!dha"
        threat_id = "2147694235"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Vncpwdump"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "100"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\vncdump-%d" ascii //weight: 1
        $x_1_2 = "vncdumpdll.dll" ascii //weight: 1
        $x_1_3 = "InjectDll" ascii //weight: 1
        $x_1_4 = "vnc_haxxor" ascii //weight: 1
        $x_1_5 = "VNCPwdump" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

