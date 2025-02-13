rule Backdoor_MacOS_Fegrat_C_2147770261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Fegrat.C!dha"
        threat_id = "2147770261"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Fegrat"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RedFlare/rat/modules/netsweeper.(*Pinger).Close" ascii //weight: 1
        $x_1_2 = "RedFlare/rat/modules/netsweeper.expectedNetsweeperArgs" ascii //weight: 1
        $x_1_3 = "RedFlare/rat/platforms/darwin.(*darwinAgent).Destroy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

