rule VirTool_WinNT_Floxif_A_2147696618_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Floxif.A"
        threat_id = "2147696618"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Floxif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\kill\\Driver\\i386\\KILLPRC.pdb" ascii //weight: 1
        $x_1_2 = {8d 41 05 53 8a 51 02 84 d2 74 08 30 50 ff 8a 51 02 30 10 8a 50 ff 8a 18 f6 d2 f6 d3 88 50 ff 88 18 84 d2 75 04 84 db 74 04}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

