rule HackTool_Linux_RemoteServices_AM_2147762612_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/RemoteServices.AM!!WinExeExecution"
        threat_id = "2147762612"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "RemoteServices"
        severity = "High"
        info = "WinExeExecution: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "winexe.c" ascii //weight: 1
        $x_1_2 = "winexe_out_pipe_send" ascii //weight: 1
        $x_1_3 = "winexe_ctrl_opened" ascii //weight: 1
        $x_1_4 = "winexe version %d" ascii //weight: 1
        $x_1_5 = "winexesvc.exe" ascii //weight: 1
        $x_1_6 = "[DOMAIN\\]USERNAME%PASSWORD" ascii //weight: 1
        $x_1_7 = "winexesvc64_exe" ascii //weight: 1
        $x_1_8 = "winexesvc_launch.c" ascii //weight: 1
        $x_1_9 = "winexesvcStart" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

