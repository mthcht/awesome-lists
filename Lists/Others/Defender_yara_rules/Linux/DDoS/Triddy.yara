rule DDoS_Linux_Triddy_A_2147827549_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Triddy.A!xp"
        threat_id = "2147827549"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Triddy"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "TRUMP IS DADDY" ascii //weight: 2
        $x_1_2 = "webfuck" ascii //weight: 1
        $x_1_3 = "hlLjztqZ" ascii //weight: 1
        $x_1_4 = "npxXoudifFeEgGaACScs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

