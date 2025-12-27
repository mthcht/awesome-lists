rule VirTool_Win64_EDRFreeze_A_2147953696_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:Win64/EDRFreeze.A"
        threat_id = "2147953696"
        type = "VirTool"
        platform = "Win64: Windows 64-bit platform"
        family = "EDRFreeze"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Failed to create PPL process" wide //weight: 1
        $x_1_2 = {46 00 61 00 69 00 6c 00 65 00 64 00 20 00 74 00 6f 00 20 00 65 00 6e 00 61 00 62 00 6c 00 65 00 20 00 64 00 65 00 62 00 75 00 67 00 20 00 70 00 72 00 69 00 76 00 69 00 6c 00 65 00 67 00 65 00 2e 00 0a}  //weight: 1, accuracy: High
        $x_1_3 = {4b 00 69 00 6c 00 6c 00 20 00 57 00 45 00 52 00 20 00 73 00 75 00 63 00 63 00 65 00 73 00 73 00 66 00 75 00 6c 00 6c 00 79 00 2e 00 20 00 50 00 49 00 44 00 3a 00 20}  //weight: 1, accuracy: High
        $x_1_4 = {2f 00 65 00 6e 00 63 00 66 00 69 00 6c 00 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

