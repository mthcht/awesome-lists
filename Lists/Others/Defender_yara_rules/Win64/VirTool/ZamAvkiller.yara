rule VirTool_Win64_ZamAvkiller_A_2147917293_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ZamAvkiller.A"
        threat_id = "2147917293"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ZamAvkiller"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.loaddriv" ascii //weight: 1
        $x_1_2 = "edrcheck.deferwrap" ascii //weight: 1
        $x_1_3 = "edrlistcheck" ascii //weight: 1
        $x_1_4 = "DeviceIoControl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

