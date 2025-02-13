rule HackTool_Win32_UACBypass_A_2147776441_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/UACBypass.A"
        threat_id = "2147776441"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypass"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DelegateExecute" wide //weight: 1
        $x_1_2 = "Classes\\ms-settings\\shell\\open\\command" wide //weight: 1
        $x_1_3 = "UAC_Bypass" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Win32_UACBypass_LKV_2147851155_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win32/UACBypass.LKV!MTB"
        threat_id = "2147851155"
        type = "HackTool"
        platform = "Win32: Windows 32-bit platform"
        family = "UACBypass"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "iscsicpl_bypassUAC-main\\Debug\\iscsiexe.pdb" ascii //weight: 1
        $x_1_2 = "iscsiexe_org.ServiceMain" ascii //weight: 1
        $x_1_3 = "iscsiexe_org.DiscpEstablishServiceLinkage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

