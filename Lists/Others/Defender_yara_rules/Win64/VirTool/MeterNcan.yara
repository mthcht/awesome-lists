rule VirTool_Win64_MeterNcan_A_2147967409_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterNcan.A"
        threat_id = "2147967409"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterNcan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\.\\pipe\\%08x%08x\\pipe\\srvsvc" ascii //weight: 1
        $x_1_2 = "\\\\.\\pipe\\%08x%08x\\pipe\\spoolss" ascii //weight: 1
        $x_1_3 = "\\\\localhost\\pipe\\%08x%08x" ascii //weight: 1
        $x_1_4 = "\\lsass.exe" ascii //weight: 1
        $x_1_5 = "ncacn_np" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

