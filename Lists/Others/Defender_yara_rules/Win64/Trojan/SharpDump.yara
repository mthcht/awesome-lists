rule Trojan_Win64_SharpDump_Z_2147973488_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SharpDump.Z!MTB"
        threat_id = "2147973488"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SharpDump"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SharpDump" ascii //weight: 1
        $x_1_2 = "MiniDumpWriteDump" ascii //weight: 1
        $x_1_3 = "SharpDump.Tests" ascii //weight: 1
        $x_1_4 = "ReadAllBytes" ascii //weight: 1
        $x_1_5 = "FileShare" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

