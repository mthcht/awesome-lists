rule HackTool_Linux_Portscan_B_2147828991_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Portscan.B!xp"
        threat_id = "2147828991"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Portscan"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {55 48 89 e5 53 48 83 ec 68 89 7d 9c 48 89 75 90 64 48 8b 04 25 28 00 00 00 48 89 45 e8 31 c0 83 7d 9c 05}  //weight: 1, accuracy: High
        $x_1_2 = {48 8b 45 c0 48 89 45 c8 48 8b 45 c8 0f b6 40 09 3c 11 75 a0 48 8b 45 c8 0f b6 00 83 e0 0f 0f b6 c0 c1 e0 02 66 89 45 ae 0f b7 55 ae 48 8b 45 c0 48 01 d0 48 89 45 d0}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule HackTool_Linux_Portscan_C_2147829078_0
{
    meta:
        author = "defender2yara"
        detection_name = "HackTool:Linux/Portscan.C!xp"
        threat_id = "2147829078"
        type = "HackTool"
        platform = "Linux: Linux platform"
        family = "Portscan"
        severity = "High"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 61 6e 20 69 6e 20 50 72 6f 67 72 65 73 73 20 00}  //weight: 1, accuracy: High
        $x_1_2 = {e8 00 00 00 86 f7 ff ff 08 01 00 00 fd f8}  //weight: 1, accuracy: High
        $x_1_3 = {64 00 5f 73 74 61 72 74 00 68 6f 73 74}  //weight: 1, accuracy: High
        $x_1_4 = {c7 45 b0 10 00 00 00 48 8d 4d b0 48 8d 55 e0 48 8b 75 c0 8b 45 b4}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

