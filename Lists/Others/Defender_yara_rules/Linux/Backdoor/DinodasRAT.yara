rule Backdoor_Linux_DinodasRAT_A_2147899718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/DinodasRAT.A!MTB"
        threat_id = "2147899718"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "DinodasRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inifile.cpp" ascii //weight: 1
        $x_1_2 = "chkconfig --list | grep %s" ascii //weight: 1
        $x_1_3 = "myshell.cpp" ascii //weight: 1
        $x_1_4 = "chkconfig --del %s" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

