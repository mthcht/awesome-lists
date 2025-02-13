rule HackTool_Win32_Clownall_2147624432_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Clownall"
        threat_id = "2147624432"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Clownall"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-W|tch-Doct0r-" ascii //weight: 1
        $x_1_2 = "A*\\AC:\\Program Files\\Microsoft Visual Studio\\VB98\\VB Projects\\Clown Call\\Clown Call.vbp" wide //weight: 1
        $x_1_3 = "Dialing" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

