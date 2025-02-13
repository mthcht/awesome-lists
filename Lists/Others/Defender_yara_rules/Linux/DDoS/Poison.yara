rule DDoS_Linux_Poison_A_2147830766_0
{
    meta:
        author = "defender2yara"
        detection_name = "DDoS:Linux/Poison.A!xp"
        threat_id = "2147830766"
        type = "DDoS"
        platform = "Linux: Linux platform"
        family = "Poison"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RFPoison.c" ascii //weight: 1
        $x_1_2 = "Poison packet" ascii //weight: 1
        $x_1_3 = "rfpoison <ip of target>" ascii //weight: 1
        $x_1_4 = "\\*SMBSERVER" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

