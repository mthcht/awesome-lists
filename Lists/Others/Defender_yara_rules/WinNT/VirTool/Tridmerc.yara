rule VirTool_WinNT_Tridmerc_A_2147607403_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Tridmerc.gen!A"
        threat_id = "2147607403"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Tridmerc"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 04 80 7b 2a 57 8b 7d 24 89 1f 89 5f 04 0f 84 fc 00 00 00 83 e8 04 0f 84 ad 00 00 00 83 e8 18 74 0b c7 07 10 00 00 c0}  //weight: 1, accuracy: High
        $x_1_2 = {7d 04 8b f8 eb 3c b8 b6 04 01 00 89 46 70 89 46 40 89 46 38 89 46 78 c7 46 34 00 03 01 00 ff 15}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\Coding\\drv4srv\\msdirect.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

