rule Trojan_WinNT_Winnti_C_2147711358_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:WinNT/Winnti.C!dha"
        threat_id = "2147711358"
        type = "Trojan"
        platform = "WinNT: WinNT"
        family = "Winnti"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "smalled.fon" wide //weight: 1
        $x_1_2 = {57 ff d3 83 c4 0c 33 d2 66 89 97 fe 01 00 00 33 c0 56 89}  //weight: 1, accuracy: High
        $x_1_3 = {56 ff d3 33 c9 8d be 00 04 00 00 83 c4 0c 66 89 8e fe 01 00 00 85 ff 74 19}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

