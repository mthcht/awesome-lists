rule HackTool_Win32_NoFilter_A_2147888243_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/NoFilter.A"
        threat_id = "2147888243"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "NoFilter"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\Debug\\NoFilter.pdb" ascii //weight: 1
        $x_1_2 = "fwpuclnt.dll" ascii //weight: 1
        $x_1_3 = {48 83 ec 28 48 8d 05 ?? ?? ?? ?? 48 83 c0 08 4c 8b c8 4c 8d 05 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? b9 06 00 00 00 e8 d6 05 00 00 48 83 c4 28 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

