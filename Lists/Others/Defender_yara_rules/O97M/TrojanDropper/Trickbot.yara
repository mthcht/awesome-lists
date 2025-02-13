rule TrojanDropper_O97M_Trickbot_G_2147765674_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Trickbot.G!MSR"
        threat_id = "2147765674"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Trickbot"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Speak.Write FaxInfo.Cicles" ascii //weight: 1
        $x_1_2 = "Exec \"explorer.exe C:\\Battle\\Themes.vbs\"" ascii //weight: 1
        $x_2_3 = {4d 73 67 42 6f 78 28 22 44 6f 20 79 6f 75 20 72 65 61 6c 6c 79 20 22 20 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 26 20 22 77 61 6e 74 20 74 6f 20 63 6c 6f 73 65 20 74 68 65 20 64 6f 63 75 6d 65 6e 74 3f 22 2c 20 5f ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? 76 62 59 65 73 4e 6f 29}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

