rule VirTool_Win64_MeterSrvpip_A_2147967412_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterSrvpip.A"
        threat_id = "2147967412"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterSrvpip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\\\%s\\pipe\\%s" ascii //weight: 1
        $x_1_2 = "AddMandatoryAce" ascii //weight: 1
        $x_1_3 = "PACKET TRANSMIT" ascii //weight: 1
        $x_1_4 = "PACKET RECEIVE" ascii //weight: 1
        $x_1_5 = "insufficient memory" ascii //weight: 1
        $x_1_6 = "CreateRemoteThread" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

