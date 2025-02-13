rule Trojan_Linux_Morcut_A_2147823256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Morcut.A!xp"
        threat_id = "2147823256"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Morcut"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vntype.src" ascii //weight: 1
        $x_1_2 = "VIQR 1.1" ascii //weight: 1
        $x_1_3 = "Usage: vn8to7 [-com <c>] [-m" ascii //weight: 1
        $x_1_4 = "usage: -com [char" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

