rule VirTool_Win64_GoclpC2_A_2147944839_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/GoclpC2.A"
        threat_id = "2147944839"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "GoclpC2"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".executeCommand" ascii //weight: 1
        $x_1_2 = ".getProcessList" ascii //weight: 1
        $x_1_3 = ".NewClient" ascii //weight: 1
        $x_1_4 = ".NewKeylogger" ascii //weight: 1
        $x_1_5 = ".detectEnvironment" ascii //weight: 1
        $x_1_6 = ".testClipboardRedirection" ascii //weight: 1
        $x_1_7 = ".captureScreenshot" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

