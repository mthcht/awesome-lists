rule Backdoor_Linux_BrickStorm_A_2147960192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/BrickStorm.A!MTB"
        threat_id = "2147960192"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "BrickStorm"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.ofcfjpoimmjefnhjjehn.func14" ascii //weight: 1
        $x_1_2 = "main.ocfepobhhcffnebdpeaf.func1" ascii //weight: 1
        $x_1_3 = "main.fnffeleicfgdcnomjddp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

