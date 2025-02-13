rule TrojanClicker_MSIL_Youclick_A_2147690204_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Youclick.A"
        threat_id = "2147690204"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Youclick"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "YoutubeBrowser.Form1.resources" ascii //weight: 3
        $x_3_2 = "InetCpl.cpl,ClearMyTracksByProcess 4351" wide //weight: 3
        $x_1_3 = "/backgound/img/link0.php" wide //weight: 1
        $x_3_4 = "\\x86\\Release\\swhost.pdb" ascii //weight: 3
        $x_1_5 = "/background/IMG/user_agent.php" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 1 of ($x_1_*))) or
            ((3 of ($x_3_*))) or
            (all of ($x*))
        )
}

