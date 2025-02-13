rule Backdoor_Linux_Fysbis_A_2147708983_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/Fysbis.A!dha"
        threat_id = "2147708983"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "Fysbis"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "ls /etc | egrep -e\"fedora*|debian*|gentoo*|mandriva*|mandrake*|meego*|redhat*|lsb-*|sun-*|SUSE*|release\"" ascii //weight: 2
        $x_2_2 = "pgrep -l \"gnome|kde|mate|cinnamon|lxde|xfce|jwm\"" ascii //weight: 2
        $x_1_3 = {00 31 31 52 65 6d 6f 74 65 53 68 65 6c 6c 00}  //weight: 1, accuracy: High
        $x_1_4 = "Your command not writed to pipe" ascii //weight: 1
        $x_1_5 = "Terminal don`t started" ascii //weight: 1
        $x_1_6 = "Terminal don`t stopped" ascii //weight: 1
        $x_1_7 = "Terminal yet started" ascii //weight: 1
        $x_1_8 = "Terminal yet stopped" ascii //weight: 1
        $x_1_9 = "Terminal don`t started for executing command" ascii //weight: 1
        $x_1_10 = "<caption><font size=4 color=red>TABLE EXECUTE FILES</font></caption>" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((5 of ($x_1_*))) or
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

