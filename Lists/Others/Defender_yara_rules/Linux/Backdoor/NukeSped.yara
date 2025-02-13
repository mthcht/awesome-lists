rule Backdoor_Linux_NukeSped_A_2147764078_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/NukeSped.A!MTB"
        threat_id = "2147764078"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "NukeSped"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "waitpid" ascii //weight: 1
        $x_1_2 = "webident_f" ascii //weight: 1
        $x_1_3 = "fudcitydelivers.com/net.php" ascii //weight: 1
        $x_1_4 = "sctemarkets.com/net.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

