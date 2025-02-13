rule Trojan_MSIL_Eybot_A_2147721715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Eybot.A!bit"
        threat_id = "2147721715"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Eybot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "EyeBotServer\\obj\\Debug\\EyeBotServer.pdb" ascii //weight: 1
        $x_1_3 = "http://www.pc-tune.ch/getip.php" wide //weight: 1
        $x_1_4 = "\\steamconfig.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

