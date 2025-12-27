rule VirTool_Win64_SuspResolveAPI_A_2147955409_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/SuspResolveAPI.A"
        threat_id = "2147955409"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "SuspResolveAPI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 6e 74 64 6c 75 ?? 8b 44 39 04 41 0b c0 3d 6c 2e 64 6c 75 ?? 0f b7 44 39 08 66 83 c8 20 66 83 f8 6c 75}  //weight: 1, accuracy: Low
        $x_1_2 = {b8 52 74 00 00 66 39 06 75}  //weight: 1, accuracy: High
        $x_1_3 = {b8 4b 69 00 00 66 39 06 75}  //weight: 1, accuracy: High
        $x_1_4 = {b8 5a 77 00 00 66 39 06 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

