rule HackTool_Win32_ProcHack_SGA_2147896512_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/ProcHack.SGA!MTB"
        threat_id = "2147896512"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "ProcHack"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "www.super-ec.cn" ascii //weight: 1
        $x_2_2 = "\\superec.ProcessMemory.sys" ascii //weight: 2
        $x_1_3 = "\\rwm.pdb" ascii //weight: 1
        $x_1_4 = "ialdnwxf" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

