rule VirTool_Win64_NSecKiller_A_2147963321_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/NSecKiller.A"
        threat_id = "2147963321"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "NSecKiller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "NSecKrnl.sys" ascii //weight: 1
        $x_1_2 = "BlackSnufkin" ascii //weight: 1
        $x_1_3 = "BYOVD Process Killer" ascii //weight: 1
        $x_1_4 = "Kills a process by name" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

