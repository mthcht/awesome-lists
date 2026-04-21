rule VirTool_Win64_MeterLan_A_2147967406_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterLan.A"
        threat_id = "2147967406"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterLan"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SRVHOST" ascii //weight: 1
        $x_1_2 = "HOSTSTART" ascii //weight: 1
        $x_1_3 = "fromIp" ascii //weight: 1
        $x_1_4 = "fromPort" ascii //weight: 1
        $x_1_5 = "PXEALTCONF" ascii //weight: 1
        $x_1_6 = "PXECONF" ascii //weight: 1
        $x_1_7 = "address in use" ascii //weight: 1
        $x_1_8 = "connection already in progress" ascii //weight: 1
        $x_1_9 = "permission denied" ascii //weight: 1
        $x_1_10 = "wrong protocol type" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

