rule VirTool_Win32_Junkdata_A_2147641421_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win32/Junkdata.A"
        threat_id = "2147641421"
        type = "VirTool"
        platform = "Win32: Windows 32-bit platform"
        family = "Junkdata"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {99 b9 ff 00 00 00 f7 f9 83 c7 01 3b ?? 88 54 37 ff 7c e8}  //weight: 1, accuracy: Low
        $x_1_2 = {80 04 30 ff 83 c0 01 3b ?? 7c f5}  //weight: 1, accuracy: Low
        $x_1_3 = {b9 1f 00 00 00 f7 f1 85 d2 0f 85 ?? ?? 00 00 8b 4c 24 ?? 8b d1 83 e2 0f 80 fa 08 74}  //weight: 1, accuracy: Low
        $x_1_4 = {2d 64 20 00 2d 73 20 00 6d 64 35}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

