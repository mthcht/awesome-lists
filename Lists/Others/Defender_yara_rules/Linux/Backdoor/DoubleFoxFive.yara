rule Backdoor_Linux_DoubleFoxFive_A_2147759925_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/DoubleFoxFive.A!dha"
        threat_id = "2147759925"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "DoubleFoxFive"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.(*Agent).Start" ascii //weight: 1
        $x_1_2 = "main.(*Agent).connectToRemote" ascii //weight: 1
        $x_1_3 = "main.(*Agent).shell" ascii //weight: 1
        $x_1_4 = "main.(*Agent).execute" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

