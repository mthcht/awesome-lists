rule VirTool_Win64_MeterPowerps_A_2147967408_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterPowerps.A"
        threat_id = "2147967408"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterPowerps"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CorBindToRuntime" ascii //weight: 1
        $x_1_2 = "MSF.Powershell.Runner" ascii //weight: 1
        $x_1_3 = "CLRCreateInstance" ascii //weight: 1
        $x_1_4 = "PS > " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

