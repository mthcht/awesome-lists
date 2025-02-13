rule Backdoor_Linux_FireBack_A_2147819261_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Linux/FireBack.A!xp"
        threat_id = "2147819261"
        type = "Backdoor"
        platform = "Linux: Linux platform"
        family = "FireBack"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deadlynose" ascii //weight: 1
        $x_1_2 = "cz00bek's Simple Backdoor" ascii //weight: 1
        $x_1_3 = "Use: %s <port>" ascii //weight: 1
        $x_1_4 = "Spawning shell..." ascii //weight: 1
        $x_1_5 = "sback.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

