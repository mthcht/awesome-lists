rule VirTool_Win64_SearchSyscall_A_2147955404_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/SearchSyscall.A"
        threat_id = "2147955404"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SearchSyscall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 8b d9 66 c7 44 24 ?? 0f 05 c6 44 24 ?? c3 45 33 d2 4d 63 da 48 8d 4c 24 ?? 4c 03 db 41 b8 03 00 00 00 49 8b d3 e8 ?? ?? ?? ?? 85 c0 74 0d 41 ff c2 41 83 fa 20 7c da 33 c0 eb 03 49 8b c3 48 83 c4 20 5b c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_Win64_SearchSyscall_B_2147955405_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/SearchSyscall.B"
        threat_id = "2147955405"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SearchSyscall"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 c7 44 24 ?? 0f 05 44 0f b7 44 24 ?? 41 b1 c3 33 c0 48 63 d0 66 44 3b 04 0a 75 07 44 3a 4c 0a 02 74 0a ff c0 83 f8 20 7c e8 33 c0 c3}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

