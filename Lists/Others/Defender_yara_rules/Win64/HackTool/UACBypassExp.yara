rule HackTool_Win64_UACBypassExp_SH_2147958283_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/UACBypassExp.SH!MTB"
        threat_id = "2147958283"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "UACBypassExp"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UAC Bypass Demonstration Tool" wide //weight: 1
        $x_1_2 = "Masquerading current process" ascii //weight: 1
        $x_1_3 = "Harold\\source\\repos\\gw\\x64\\Release\\test02.pdb" ascii //weight: 1
        $x_1_4 = "Successfully created payload process" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

