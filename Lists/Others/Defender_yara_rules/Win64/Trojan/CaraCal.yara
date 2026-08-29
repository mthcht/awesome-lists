rule Trojan_Win64_CaraCal_Z_2147977217_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CaraCal.Z!MTB"
        threat_id = "2147977217"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CaraCal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.InjectShellcode" ascii //weight: 1
        $x_1_2 = "main.handlePipeClient" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

