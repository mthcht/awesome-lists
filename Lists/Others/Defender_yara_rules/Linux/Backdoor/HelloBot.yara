rule Backdoor_Linux_HelloBot_A_2147818201_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/HelloBot.A!xp"
        threat_id = "2147818201"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "HelloBot"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShellTask" ascii //weight: 1
        $x_1_2 = "HISTFILE" ascii //weight: 1
        $x_1_3 = "fuck you" ascii //weight: 1
        $x_1_4 = "install_path_bak" ascii //weight: 1
        $x_1_5 = "ecfafeab6ee7d642" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

