rule TrojanClicker_Win32_Senterpud_A_2147671750_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:Win32/Senterpud.A"
        threat_id = "2147671750"
        type = "TrojanClicker"
        platform = "Win32: Windows 32-bit platform"
        family = "Senterpud"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "D:\\Prog-Photoshop\\Hack\\Hack" ascii //weight: 1
        $x_1_2 = "HackPub\\HackPub\\obj\\Debug\\Winmgt.pdb" ascii //weight: 1
        $x_1_3 = "perdusentier.byethost7.com/Service/" wide //weight: 1
        $x_1_4 = "perdusentier.legtux.org/Application/" wide //weight: 1
        $x_1_5 = ".yooclick.com/" wide //weight: 1
        $x_1_6 = "{0}\\wget.exe" wide //weight: 1
        $x_1_7 = ".exe.zip" wide //weight: 1
        $x_1_8 = "/index.php" wide //weight: 1
        $x_1_9 = {53 74 61 72 74 44 6f 77 6e 6c 6f 61 64 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

