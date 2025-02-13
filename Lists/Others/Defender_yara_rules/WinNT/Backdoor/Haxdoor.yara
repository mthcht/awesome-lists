rule Backdoor_WinNT_Haxdoor_A_2147624445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Haxdoor.gen!A"
        threat_id = "2147624445"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Haxdoor"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {66 39 10 74 07 2d 00 10 00 00 eb}  //weight: 1, accuracy: High
        $x_1_2 = {83 ee 05 89 72 01 8b 81 ?? ?? ?? ?? 66 83 38 8b}  //weight: 1, accuracy: Low
        $x_1_3 = {42 ba 77 77 77 2e 39 11 75}  //weight: 1, accuracy: High
        $x_1_4 = {83 fa 0b 76 1a 81 78 f6 6f 00 74 00}  //weight: 1, accuracy: High
        $x_1_5 = {82 1c 05 46 e8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

