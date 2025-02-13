rule HackTool_Win32_Scanly_A_2147753573_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Scanly.A!dha"
        threat_id = "2147753573"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Scanly"
        severity = "High"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Usage: %s [-s startip] [-e endip] [-p port] [-t timeout] [-n maxthreadnum] [-l logfile]" ascii //weight: 3
        $x_2_2 = "%-40s Vendor[%s]Version[%u]HostName[%s]" ascii //weight: 2
        $x_2_3 = "\\myscan_ver.pdb" ascii //weight: 2
        $x_1_4 = "debug mssql check 1" ascii //weight: 1
        $x_1_5 = "[Found:] %s Port: %d open." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

