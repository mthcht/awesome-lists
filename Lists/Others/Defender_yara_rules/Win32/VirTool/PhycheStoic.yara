rule VirTool_Win32_PhycheStoic_A_2147818227_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/PhycheStoic.A!MTB"
        threat_id = "2147818227"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "PhycheStoic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pneuma/commands.execute" ascii //weight: 1
        $x_1_2 = "pneuma/commands.getShellCommand" ascii //weight: 1
        $x_1_3 = "beacon.(*BeaconIncoming).GetBeacon" ascii //weight: 1
        $x_1_4 = "beacon.(*beaconClient).Handle" ascii //weight: 1
        $x_1_5 = "(*AgentConfig).BuildBeacon" ascii //weight: 1
        $x_1_6 = "(*AgentConfig).BuildSocketBeacon" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

