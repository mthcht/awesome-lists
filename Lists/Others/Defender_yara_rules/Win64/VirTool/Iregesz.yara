rule VirTool_Win64_Iregesz_A_2147975264_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/Iregesz.A"
        threat_id = "2147975264"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Iregesz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeaconID" ascii //weight: 1
        $x_1_2 = "beaconFormatReset" ascii //weight: 1
        $x_1_3 = "beaconGetValue" ascii //weight: 1
        $x_1_4 = "defaultProfile" ascii //weight: 1
        $x_1_5 = "applyPatchedTarget" ascii //weight: 1
        $x_1_6 = "EncryptHeartbeat" ascii //weight: 1
        $x_1_7 = "StartShellJob" ascii //weight: 1
        $x_1_8 = "StartTunnelTask" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

