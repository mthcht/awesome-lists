rule Backdoor_Linux_EvilGnome_A_2147773343_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/EvilGnome.gen!A!!EvilGnome.gen!A"
        threat_id = "2147773343"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "EvilGnome"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        info = "EvilGnome: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ShooterSound" ascii //weight: 1
        $x_1_2 = "ShooterImage" ascii //weight: 1
        $x_1_3 = "ShooterFile" ascii //weight: 1
        $x_1_4 = "gnome-shell-ext" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

