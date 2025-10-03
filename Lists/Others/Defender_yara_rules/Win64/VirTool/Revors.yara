rule VirTool_Win64_Revors_A_2147953934_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Revors.A"
        threat_id = "2147953934"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Revors"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "registerBeacon" ascii //weight: 1
        $x_1_2 = "httpproxypassword" ascii //weight: 1
        $x_1_3 = "beaconTaskRetrieve" ascii //weight: 1
        $x_1_4 = "hostEndpoint" ascii //weight: 1
        $x_1_5 = "autorouteMessage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

