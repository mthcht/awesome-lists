rule Backdoor_Linux_HiddenWasp_A_2147776296_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/HiddenWasp.gen!A!!HiddenWasp.gen!A"
        threat_id = "2147776296"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "HiddenWasp"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "HiddenWasp: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "libse1inux" ascii //weight: 10
        $x_1_2 = "I_AM_HIDDEN" ascii //weight: 1
        $x_1_3 = "HIDE_THIS_SHELL" ascii //weight: 1
        $x_1_4 = "xxd " ascii //weight: 1
        $x_1_5 = "ifup-local" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

