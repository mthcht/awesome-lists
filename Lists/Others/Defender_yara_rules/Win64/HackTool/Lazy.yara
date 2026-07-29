rule HackTool_Win64_Lazy_MK_2147974771_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Lazy.MK!MTB"
        threat_id = "2147974771"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Lazy"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "[-] inject code:" ascii //weight: 10
        $x_5_2 = "[success] Injected" ascii //weight: 5
        $x_3_3 = "\\Andromeda-CS2-Base-master" ascii //weight: 3
        $x_2_4 = "[error] GetPrivileges Or Dll Not Found" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

