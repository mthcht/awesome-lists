rule VirTool_Win64_ThreadJacker_E_2147955375_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ThreadJacker.E"
        threat_id = "2147955375"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ThreadJacker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inject-shellcode" ascii //weight: 1
        $x_1_2 = "NtCreateThread injection method" ascii //weight: 1
        $x_1_3 = "Memory allocation size" ascii //weight: 1
        $x_1_4 = "Delivery Method" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

