rule VirTool_Win64_Comenesz_A_2147958319_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Comenesz.A"
        threat_id = "2147958319"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Comenesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Agent registered" ascii //weight: 1
        $x_1_2 = "sleepFoliage" ascii //weight: 1
        $x_1_3 = "takeScreenshot" ascii //weight: 1
        $x_1_4 = "@Impersonated" ascii //weight: 1
        $x_1_5 = "Jitter" ascii //weight: 1
        $x_1_6 = "@CMD_STEAL_TOKEN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

