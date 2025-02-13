rule HackTool_Win64_Crdrpi_W_2147817639_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Win64/Crdrpi.W!MTB"
        threat_id = "2147817639"
        type = "HackTool"
        platform = "Win64: Windows 64-bit platform"
        family = "Crdrpi"
        severity = "High"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SYSTEM\\ControlSet001\\Services\\PortProxy\\v4tov4\\tcp" ascii //weight: 1
        $x_1_2 = "IpHlpSvc" ascii //weight: 1
        $x_1_3 = "PortProxy" ascii //weight: 1
        $x_1_4 = "ControlService" ascii //weight: 1
        $x_1_5 = "OpenSCManagerA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

