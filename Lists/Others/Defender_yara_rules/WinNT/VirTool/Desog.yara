rule VirTool_WinNT_Desog_A_2147609750_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Desog.A"
        threat_id = "2147609750"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Desog"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 ff 89 3d d0 32 01 00 74 30 8b 45 fc 8d 73 0c 8d 48 02 33 c0 8b d1 c1 e9 02 f3 ab 8b ca 83 e1 03 f3 aa 8b 4b 08 8b 3d d0 32 01 00 8b c1 c1 e9 02 f3 a5 8b c8 83 e1 03 f3 a4}  //weight: 1, accuracy: High
        $x_1_2 = {80 30 8d 8a 18 88 58 fc 40 e2 f5}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

