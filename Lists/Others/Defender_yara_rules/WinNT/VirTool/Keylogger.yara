rule VirTool_WinNT_Keylogger_FE_2147617689_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Keylogger.FE"
        threat_id = "2147617689"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3d 80 21 10 80 75}  //weight: 1, accuracy: High
        $x_1_2 = {81 f9 80 21 10 80 75}  //weight: 1, accuracy: High
        $x_1_3 = {3d 84 21 10 80 75}  //weight: 1, accuracy: High
        $x_1_4 = {81 f9 84 21 10 80 75}  //weight: 1, accuracy: High
        $x_4_5 = {68 ed 00 00 00 6a 60 ff 15}  //weight: 4, accuracy: High
        $x_4_6 = {6d 73 65 70 73 2e 70 64 62 00}  //weight: 4, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule VirTool_WinNT_Keylogger_B_2147639082_0
{
    meta:
        author = "defender2yara"
        detection_name = "VirTool:WinNT/Keylogger.B"
        threat_id = "2147639082"
        type = "VirTool"
        platform = "WinNT: WinNT"
        family = "Keylogger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 3d 45 00 74 0c 66 3d 3a 00 74 06 66 3d 46 00 75 ?? 0f b7 c0 83 e8 3a 74 ?? 83 e8 0b}  //weight: 2, accuracy: Low
        $x_1_2 = {68 ed 00 00 00 6a 60 ff d6}  //weight: 1, accuracy: High
        $x_1_3 = "\\Device\\KeyboardClass0" wide //weight: 1
        $x_1_4 = "\\BaseNamedObjects\\Global\\YxnKbEvent" wide //weight: 1
        $x_1_5 = {00 4b 65 79 44 77 6f 6e 3a 20 30 78 25 78}  //weight: 1, accuracy: High
        $x_1_6 = "\\DDKPasswordListenner\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_1_*))) or
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

