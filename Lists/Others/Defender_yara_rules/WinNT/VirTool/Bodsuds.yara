rule VirTool_WinNT_Bodsuds_A_2147623521_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Bodsuds.A"
        threat_id = "2147623521"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Bodsuds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {83 f9 32 7c e8 eb b7 83 c0 05 8b 08 8d 4c 01 04 81 79 01 ff 55 8b ec 89 4c 24 04 74 19}  //weight: 1, accuracy: High
        $x_1_2 = {83 fa 30 7c e8 eb e0 83 c0 05 8b 10 8d 54 02 04}  //weight: 1, accuracy: High
        $x_1_3 = {bf 10 00 00 c0 74 4f 81 f9 4b e1 22 00 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

