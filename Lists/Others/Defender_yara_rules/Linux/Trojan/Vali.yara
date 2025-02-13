rule Trojan_Linux_Vali_A_2147819486_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Vali.A!xp"
        threat_id = "2147819486"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Vali"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/tmp/.vali" ascii //weight: 1
        $x_1_2 = "Malicious code..." ascii //weight: 1
        $x_1_3 = "***Infected %s." ascii //weight: 1
        $x_1_4 = "Vali here..." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

