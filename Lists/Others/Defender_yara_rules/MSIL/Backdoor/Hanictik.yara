rule Backdoor_MSIL_Hanictik_A_2147684448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Hanictik.A"
        threat_id = "2147684448"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hanictik"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "{0:0.##} {1}" wide //weight: 1
        $x_1_2 = "grabber_snapshot" wide //weight: 1
        $x_1_3 = "DisableSR" wide //weight: 1
        $x_1_4 = "set CDAudio door open" wide //weight: 1
        $x_1_5 = "\\dmplogs\\" wide //weight: 1
        $x_1_6 = "/C ping 1.1.1.1 -n 1 -w 5000 > Nul & Del " wide //weight: 1
        $x_1_7 = "Remote Chat" wide //weight: 1
        $x_1_8 = "Slowloris" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

