rule Backdoor_MSIL_Famtrat_A_2147723260_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Famtrat.A!bit"
        threat_id = "2147723260"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Famtrat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "ezmoneyez.ddns.net" wide //weight: 3
        $x_2_2 = "\\FARATCLIENT\\obj\\Debug\\FARATCLIENT.pdb" ascii //weight: 2
        $x_2_3 = "FAVIRUS:" wide //weight: 2
        $x_1_4 = "fastayko.chickenkiller.com" ascii //weight: 1
        $x_1_5 = "GrabDesktop" ascii //weight: 1
        $x_1_6 = "SendDesktopImage" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

