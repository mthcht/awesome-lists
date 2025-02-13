rule Backdoor_MSIL_Proxbot_A_2147722442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Proxbot.A!bit"
        threat_id = "2147722442"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Proxbot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "/Botswag/Settings/" wide //weight: 1
        $x_1_2 = "http://psykooo.ddns.net" wide //weight: 1
        $x_1_3 = "/rat.php" wide //weight: 1
        $x_1_4 = "/tasklist.php?Hwid=" wide //weight: 1
        $x_1_5 = {6d 00 73 00 67 00 ?? ?? 6d 00 64 00 70 00 ?? ?? 75 00 6e 00 69 00 73 00 74 00 ?? ?? 70 00 72 00 6f 00 78 00 79 00 ?? ?? 6d 00 61 00 6a 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

