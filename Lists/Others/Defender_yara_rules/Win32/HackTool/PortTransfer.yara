rule HackTool_Win32_PortTransfer_2147696307_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/PortTransfer"
        threat_id = "2147696307"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PortTransfer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Accept a Connection From Left" ascii //weight: 1
        $x_1_2 = "PortTransfer.exe" ascii //weight: 1
        $x_1_3 = "Coded by blacksplit" ascii //weight: 1
        $x_1_4 = "PortTransfer\\Release\\PortTransfer.pdb" ascii //weight: 1
        $x_1_5 = "Create Thread Success." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

