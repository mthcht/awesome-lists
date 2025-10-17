rule VirTool_Win32_SuspResolveAPI_A_2147955410_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/SuspResolveAPI.A"
        threat_id = "2147955410"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "SuspResolveAPI"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 cf 20 20 20 20 81 ff 6e 74 64 6c 75 ?? 8b 7a 04 81 cf 20 20 20 20 81 ff 6c 2e 64 6c 75 ?? 66 8b 52 08 66 83 ca 20 66 83 fa 6c 75}  //weight: 1, accuracy: Low
        $x_1_2 = {ba 4b 69 00 00 66 3b c2 75}  //weight: 1, accuracy: High
        $x_1_3 = {ba 52 74 00 00 66 3b c2 75}  //weight: 1, accuracy: High
        $x_1_4 = {b8 5a 77 00 00 66 39 01 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

