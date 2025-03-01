rule Backdoor_Linux_WireNet_A_2147815026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/WireNet.A!xp"
        threat_id = "2147815026"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "WireNet"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s/.opera/wand.dat" ascii //weight: 1
        $x_1_2 = "%s/.mozilla/seamonkey/profiles.ini" ascii //weight: 1
        $x_1_3 = "select * from moz_logins" ascii //weight: 1
        $x_1_4 = "%s/.config/autostart" ascii //weight: 1
        $x_1_5 = "encryptedPassword" ascii //weight: 1
        $x_1_6 = "crontab /tmp/nctf.txt" ascii //weight: 1
        $x_1_7 = "%s/.thunderbird/profiles.ini" ascii //weight: 1
        $x_1_8 = "%s/.xinitrc" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

