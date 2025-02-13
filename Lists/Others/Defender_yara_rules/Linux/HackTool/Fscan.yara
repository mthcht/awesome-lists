rule HackTool_Linux_Fscan_A_2147917119_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Fscan.A!MTB"
        threat_id = "2147917119"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Fscan"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "shadow1ng/fscan" ascii //weight: 1
        $x_1_2 = "Plugins.exploit" ascii //weight: 1
        $x_1_3 = "exploit-db" ascii //weight: 1
        $x_1_4 = "hackgov" ascii //weight: 1
        $x_1_5 = "Plugins.Brutelist" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

