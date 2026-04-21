rule VirTool_Win64_MeterPreInject_A_2147967407_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/MeterPreInject.A"
        threat_id = "2147967407"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "MeterPreInject"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "There was an error, shellcode not injected" ascii //weight: 1
        $x_1_2 = "The architecture of the file is incompatible with the selected payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

