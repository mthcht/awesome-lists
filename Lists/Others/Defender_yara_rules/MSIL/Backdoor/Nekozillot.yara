rule Backdoor_MSIL_Nekozillot_A_2147724891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Nekozillot.A!bit"
        threat_id = "2147724891"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Nekozillot"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Local\\Amigo\\User Data\\Default\\History" wide //weight: 1
        $x_1_2 = "http://zillot.kz/System/mysql/users.php" wide //weight: 1
        $x_1_3 = "regsetauto" wide //weight: 1
        $x_1_4 = "RisingForce2" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

