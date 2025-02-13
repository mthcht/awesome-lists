rule HackTool_Win32_NetCatTool_LK_2147843487_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NetCatTool.LK!MTB"
        threat_id = "2147843487"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NetCatTool"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "netcat\\Release\\netcat.pdb" ascii //weight: 1
        $x_1_2 = "detach from console" ascii //weight: 1
        $x_1_3 = "sent %d, rcvd %d" ascii //weight: 1
        $x_1_4 = "nc [-options] hostname port[s] [ports]" ascii //weight: 1
        $x_1_5 = "inbound program to exec [dangerous!!]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

