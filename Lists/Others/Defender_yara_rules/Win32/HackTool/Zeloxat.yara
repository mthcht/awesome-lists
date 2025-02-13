rule HackTool_Win32_Zeloxat_A_2147688269_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/Zeloxat.A"
        threat_id = "2147688269"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Zeloxat"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "-listen port1 port2" ascii //weight: 1
        $x_1_2 = "-slave localport remoteip remoteport" ascii //weight: 1
        $x_1_3 = "-inject localport remoteip remoteport [-path exepath]" ascii //weight: 1
        $x_1_4 = "wating on port %d..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

