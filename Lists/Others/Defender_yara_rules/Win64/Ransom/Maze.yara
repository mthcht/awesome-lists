rule Ransom_Win64_Maze_GV_2147920832_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win64/Maze.GV!MTB"
        threat_id = "2147920832"
        type = "Ransom"
        platform = "Win64: Windows 64-bit platform"
        family = "Maze"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Run" ascii //weight: 1
        $x_5_2 = "main.dataMazedesktopPng" ascii //weight: 5
        $x_5_3 = "DECRYPT-FILES.txt" ascii //weight: 5
        $x_1_4 = "main.doEncrypt" ascii //weight: 1
        $x_1_5 = "main.doDecrypt" ascii //weight: 1
        $x_1_6 = "type:.eq.main.Config" ascii //weight: 1
        $x_1_7 = "os.(*Process).kill" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

