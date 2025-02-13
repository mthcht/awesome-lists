rule Worm_Win32_Mirbot_A_2147646759_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Mirbot.A"
        threat_id = "2147646759"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Mirbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "50"
        strings_accuracy = "Low"
    strings:
        $x_50_1 = {5c 6d 42 6f 74 5c [0-32] 5c 52 65 6c 65 61 73 65 5c 6d [0-15] 2e 70 64 62}  //weight: 50, accuracy: Low
        $x_50_2 = "\\mBot\\Release\\mBot.pdb" ascii //weight: 50
        $x_2_3 = "[mBot|" wide //weight: 2
        $x_2_4 = "#devbot" wide //weight: 2
        $x_2_5 = "removing bot" ascii //weight: 2
        $x_2_6 = "imspread" ascii //weight: 2
        $x_2_7 = "successfully spreading message via " ascii //weight: 2
        $x_2_8 = "_Oscar_StatusNotify" ascii //weight: 2
        $x_1_9 = "killspread" ascii //weight: 1
        $x_1_10 = "USER " wide //weight: 1
        $x_1_11 = {50 00 49 00 4e 00 47 00 20 00 3a 00 [0-50] 50 00 4f 00 4e 00 47 00 20 00 3a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_50_*))) or
            (all of ($x*))
        )
}

