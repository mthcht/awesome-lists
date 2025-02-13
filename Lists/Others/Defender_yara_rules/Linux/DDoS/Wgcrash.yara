rule DDoS_Linux_Wgcrash_A_2147820331_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Wgcrash.A!xp"
        threat_id = "2147820331"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Wgcrash"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Wingate crasher by holobyte" ascii //weight: 2
        $x_1_2 = "Usage: %s <wingate> [port" ascii //weight: 1
        $x_1_3 = "Crashing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

