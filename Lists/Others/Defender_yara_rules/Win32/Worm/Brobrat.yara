rule Worm_Win32_Brobrat_A_2147594399_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Brobrat.A"
        threat_id = "2147594399"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Brobrat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SharedDocs" wide //weight: 1
        $x_1_2 = "Music" wide //weight: 1
        $x_1_3 = {44 00 6f 00 63 00 75 00 00}  //weight: 1, accuracy: High
        $x_1_4 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_5 = "Shell\\Auto\\command =" wide //weight: 1
        $x_1_6 = ":\\Autorun.inf" wide //weight: 1
        $x_1_7 = "[Autorun]" wide //weight: 1
        $x_1_8 = "Windows Security error" wide //weight: 1
        $x_1_9 = "hentai" wide //weight: 1
        $x_1_10 = "SetComputerNameA" ascii //weight: 1
        $x_1_11 = "GetComputerNameA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

