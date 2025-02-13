rule HackTool_Win64_Rsoctun_GA_2147932199_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Rsoctun.GA!MTB"
        threat_id = "2147932199"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Rsoctun"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {83 34 90 67 48 ff c2 48 39 d3 7f f4}  //weight: 3, accuracy: High
        $x_2_2 = "/root/klpo_reverse_socks-new_logger_settings/cmd/reverse_socks" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

