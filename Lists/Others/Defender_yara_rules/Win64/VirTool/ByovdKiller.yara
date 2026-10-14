rule VirTool_Win64_ByovdKiller_A_2147980247_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ByovdKiller.A"
        threat_id = "2147980247"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ByovdKiller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "BlackSnufkin" ascii //weight: 10
        $x_10_2 = "BYOVD Process Killer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

