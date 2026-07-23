rule VirTool_Win64_AppRemoverKiller_A_2147974343_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/AppRemoverKiller.A"
        threat_id = "2147974343"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "AppRemoverKiller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AppRemover" ascii //weight: 1
        $x_1_2 = "ardrv.sys" ascii //weight: 1
        $x_10_3 = "BlackSnufkin" ascii //weight: 10
        $x_10_4 = "BYOVD Process Killer" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

