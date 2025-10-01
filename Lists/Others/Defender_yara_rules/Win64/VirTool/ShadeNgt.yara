rule VirTool_Win64_ShadeNgt_A_2147953753_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/ShadeNgt.A"
        threat_id = "2147953753"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "ShadeNgt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nightshade_build/" ascii //weight: 1
        $x_1_2 = "raw payload" ascii //weight: 1
        $x_1_3 = "chacha20poly" ascii //weight: 1
        $x_1_4 = "memoryapi::VirtualAlloc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

