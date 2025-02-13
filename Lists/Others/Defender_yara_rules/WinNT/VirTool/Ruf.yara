rule VirTool_WinNT_Ruf_A_2147626270_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Ruf.gen!A"
        threat_id = "2147626270"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Ruf"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nslfur" wide //weight: 1
        $x_1_2 = {5a 77 51 75 65 72 79 56 61 6c 75 65 4b 65 79 00 6e 74 6f 73 6b 72 6e 6c 2e 65 78 65}  //weight: 1, accuracy: High
        $x_1_3 = {e4 64 a8 02 75 fa c3 b8 00 50 00 00 eb 01 48 0b c0 75 fb c3}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

