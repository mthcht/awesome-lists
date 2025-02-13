rule VirTool_WinNT_Singu_A_2147616868_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Singu.gen!A"
        threat_id = "2147616868"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Singu"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 45 f4 8b 00 03 45 08 83 7d 14 01 89 45 e8 75 3b 8b 45 f0 8b 4f 10 0f b7 00 03 c8 8b 74 8b fc 03 75 08 8a 06 3c b8 75 4c 80 7e 09 cd 75 06 80 7e 0a 2e 74 0a 3c b8 75 3c 80 7e 05 ba 75 36}  //weight: 1, accuracy: High
        $x_1_2 = {6a 01 58 5e c9 c2 08 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

