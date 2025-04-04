rule VirTool_Linux_Sliver_A_2147888493_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Linux/Sliver.A!MTB"
        threat_id = "2147888493"
        type = "VirTool"
        platform = "Linux: Linux platform"
        family = "Sliver"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ScreenshotReq" ascii //weight: 1
        $x_1_2 = "SSHCommandReq" ascii //weight: 1
        $x_1_3 = "runtime.persistentalloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

