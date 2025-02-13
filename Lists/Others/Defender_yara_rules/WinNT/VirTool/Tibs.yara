rule VirTool_WinNT_Tibs_A_2147598456_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Tibs.gen!A"
        threat_id = "2147598456"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Tibs"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "zlclient" ascii //weight: 1
        $x_1_2 = {0f 20 c0 50 25 ff ff fe ff 0f 22 c0}  //weight: 1, accuracy: High
        $x_1_3 = {00 00 8b 55 10 66 81 3a 4d 5a}  //weight: 1, accuracy: High
        $x_3_4 = {eb 22 0f 20 c0 50 25 ff ff fe ff 0f 22 c0 c6 01 33 c6 41 01 c0 c6 41 02 c2 c6 41 03 08 88 59 04 58 0f 22 c0}  //weight: 3, accuracy: High
        $x_3_5 = {eb 91 57 56 89 75 30 e8 ?? ?? ff ff 03 f0 84 db 74 81 eb 19 3b 75 1c 75 09 c7 45 2c 06 00 00 80}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((2 of ($x_3_*))) or
            (all of ($x*))
        )
}

