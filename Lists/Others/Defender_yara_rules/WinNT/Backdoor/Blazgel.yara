rule Backdoor_WinNT_Blazgel_A_2147614434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:WinNT/Blazgel.A"
        threat_id = "2147614434"
        type = "Backdoor"
        platform = "WinNT: WinNT"
        family = "Blazgel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {81 7d fc 93 08 00 00 75 41 c7 05 ?? ?? ?? ?? a0 00 00 00 c7 05 ?? ?? ?? ?? 58 01 00 00 c7 05 ?? ?? ?? ?? 70 02 00 00 c7 05 ?? ?? ?? ?? 40 02 00 00 c7 05 ?? ?? ?? ?? 9c 00 00 00 c7 05 ?? ?? ?? ?? b0 01 00 00 e9 ?? 00 00 00 81 7d fc 28 0a 00 00 75 34}  //weight: 1, accuracy: Low
        $x_1_2 = {74 43 8b 45 fc 66 8b 00 8b d8 66 81 e3 00 f0 66 81 fb 00 30 75 1e 25 ff 0f 00 00 ff 45 f4 03 01 8b 1c 30 2b 5f 1c 3b 5d 0c 75 09 66 81 7c 30 fe c7 05 74 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

