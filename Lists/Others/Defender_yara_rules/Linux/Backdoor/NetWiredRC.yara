rule Backdoor_Linux_NetWiredRC_A_2147661505_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/NetWiredRC.A"
        threat_id = "2147661505"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "NetWiredRC"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 74 74 70 3a 2f 2f 25 73 25 73 07 25 73 00 47 45 54 20 25 73 20 48 54 54 50}  //weight: 5, accuracy: High
        $x_5_2 = "%s/.config/autostart/%s.desktop" ascii //weight: 5
        $x_5_3 = {5b 25 2e 32 64 2f 25 2e 32 64 2f 25 64 ?? 25 2e 32 64 3a 25 2e 32 64 3a 25 2e 32 64 5d}  //weight: 5, accuracy: Low
        $x_1_4 = "%s/.config/google-chrome/Default/Login" ascii //weight: 1
        $x_1_5 = "%s/.config/chromium/Default/Login" ascii //weight: 1
        $x_1_6 = "select *  from moz_logins" ascii //weight: 1
        $x_1_7 = "%s/.thunderbird/profiles.ini" ascii //weight: 1
        $x_1_8 = "%s/.opera/wand.dat" ascii //weight: 1
        $x_1_9 = "%s/.purple/accounts.xml" ascii //weight: 1
        $x_1_10 = "%s/.mozilla/firefox/profiles.ini" ascii //weight: 1
        $x_10_11 = "RGI28DQ30QB8Q1F7" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 3 of ($x_5_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

