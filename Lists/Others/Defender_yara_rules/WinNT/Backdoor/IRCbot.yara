rule Backdoor_WinNT_IRCbot_A_2147621127_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/IRCbot.gen!A"
        threat_id = "2147621127"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "IRCbot"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {7e 0c 8a 54 24 0c 30 14 31 41 3b c8 7c f4}  //weight: 2, accuracy: High
        $x_1_2 = {85 c0 74 07 b8 34 00 00 c0 eb 2e 50}  //weight: 1, accuracy: High
        $x_1_3 = {59 59 74 21 8b 45 fc be 22 00 00 c0}  //weight: 1, accuracy: High
        $x_1_4 = {73 79 73 74 65 6d 2e 65 78 65 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

