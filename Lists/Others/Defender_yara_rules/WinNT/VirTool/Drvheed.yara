rule VirTool_WinNT_Drvheed_A_2147643259_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Drvheed.A"
        threat_id = "2147643259"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Drvheed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {c6 06 68 89 7e 01 c6 46 05 c3}  //weight: 1, accuracy: High
        $x_1_2 = {0f 20 c0 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_3 = {81 20 ff ff ff fd 0f b7 56 06 83 c0 28 41 3b ca 72 ee}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule VirTool_WinNT_Drvheed_A_2147643259_1
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Drvheed.A"
        threat_id = "2147643259"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Drvheed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 20 e0 c3}  //weight: 1, accuracy: High
        $x_1_2 = {0f 20 c0 25 ff ff fe ff 0f 22 c0 c2 04 00 0f 20 c0 0d 00 00 01 00 0f 22 c0 c2 04 00}  //weight: 1, accuracy: High
        $x_1_3 = {8b 48 3c 03 c8 8b 49 50 bb 00 f0 ff ff bf 00 10 00 00 f7 c1 ff 0f 00 00 74 04 23 cb 03 cf}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 24 a9 ff ff 1f 00 74 0a 25 00 00 e0 ff 05 00 00 20 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

