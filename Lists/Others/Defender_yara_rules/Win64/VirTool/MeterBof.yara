rule VirTool_Win64_MeterBof_A_2147967403_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterBof.A"
        threat_id = "2147967403"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterBof"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "BeaconUseToken" ascii //weight: 1
        $x_1_2 = "BeaconRevertToken" ascii //weight: 1
        $x_1_3 = "BeaconIsAdmin" ascii //weight: 1
        $x_1_4 = "BeaconGetSpawnTo" ascii //weight: 1
        $x_1_5 = "BeaconSpawnTemporaryProcess" ascii //weight: 1
        $x_1_6 = "BeaconInjectProcess" ascii //weight: 1
        $x_1_7 = "BeaconInjectTemporaryProcess" ascii //weight: 1
        $x_1_8 = "BeaconCleanupProcess" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

