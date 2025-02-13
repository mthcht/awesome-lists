rule HackTool_Win64_Darkside_AA_2147898778_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Darkside.AA!MTB"
        threat_id = "2147898778"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Darkside"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SELECT * FROM Win32_Service WHERE Name = 'WinDefend'" ascii //weight: 1
        $x_1_2 = "DarkSide.exe -killdef" wide //weight: 1
        $x_1_3 = "Attempt to kill Windows Defender" wide //weight: 1
        $x_1_4 = "Darkside.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

