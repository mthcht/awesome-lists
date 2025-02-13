rule HackTool_MSIL_Windissec_L_2147898972_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Windissec.L!MTB"
        threat_id = "2147898972"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Windissec"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {61 20 f4 1c a1 30 07 5c 0b 5f 07 20 00 ?? ?? ?? 58 fe 03 0c 07 20 10 ?? ?? ?? 61 5f 07 20 00 ?? ?? ?? 61 fe 03 20 bd ?? ?? ?? 07 61 0b 13 04 07 20 fd 7c 0f 21 5f}  //weight: 5, accuracy: Low
        $x_1_2 = "Disable your Anti-Virus" ascii //weight: 1
        $x_1_3 = "sc delete faceit" ascii //weight: 1
        $x_1_4 = "root\\cimv2\\security\\MicrosoftTpm" ascii //weight: 1
        $x_1_5 = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\Windows\\WindowsUpdate\\AU" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_MSIL_Windissec_NL_2147898974_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:MSIL/Windissec.NL!MTB"
        threat_id = "2147898974"
        type = "HackTool"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Windissec"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {7e 82 00 00 04 03 07 6a 58 e0 47 06 61 20 ff ?? ?? ?? 5f 95 06 1e 64 61 0a 07 17 58 0b 07 6a 04 6e 3f da ff ff ff}  //weight: 5, accuracy: Low
        $x_1_2 = "/c sc stop vgc" ascii //weight: 1
        $x_1_3 = "Disable your Anti-Virus" ascii //weight: 1
        $x_1_4 = "sc delete faceit" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

