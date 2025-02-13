rule Backdoor_MSIL_Romabot_A_2147727565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Romabot.A!bit"
        threat_id = "2147727565"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Romabot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "linguodown2015.ddns.net" wide //weight: 1
        $x_1_2 = "http://www.troman.de/cmd/cmds.txt" wide //weight: 1
        $x_1_3 = "ZnRwOi8vd3d3LnRyb21hbi5kZS9jbWQvdXBsb2FkLw==" wide //weight: 1
        $x_1_4 = "autoscreenshots" wide //weight: 1
        $x_1_5 = "kelogger" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

