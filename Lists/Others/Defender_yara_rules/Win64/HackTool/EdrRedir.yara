rule HackTool_Win64_EdrRedir_A_2147956916_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/EdrRedir.A"
        threat_id = "2147956916"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EdrRedir"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EDR-Redir.exe <VirtualPath>" wide //weight: 1
        $x_1_2 = "CreateBindLink: (VirtualPath) <==> (BackingPath):" wide //weight: 1
        $x_1_3 = "Starting create reverse proxy bind link" wide //weight: 1
        $x_1_4 = "Remove Bind Link:" wide //weight: 1
        $x_1_5 = "\\EDR-Redir.pdb" ascii //weight: 1
        $x_1_6 = {42 66 53 65 74 75 70 46 69 6c 74 65 72 00 00 00 42 66 52 65 6d 6f 76 65 4d 61 70 70 69 6e 67}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

