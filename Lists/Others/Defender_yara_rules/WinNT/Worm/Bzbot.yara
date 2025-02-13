rule Worm_WinNT_Bzbot_A_2147626137_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:WinNT/Bzbot.A"
        threat_id = "2147626137"
        type = "Worm"
        platform = "WinNT: WinNT"
        family = "Bzbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "i386\\blazebot.pdb" ascii //weight: 1
        $x_1_2 = "\\Device\\pigsux" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

