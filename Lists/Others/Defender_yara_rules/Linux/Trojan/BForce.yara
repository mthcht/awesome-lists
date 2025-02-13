rule Trojan_Linux_BForce_A_2147830790_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/BForce.A!xp"
        threat_id = "2147830790"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "BForce"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {00 f0 ae 1c 00 f0 3e 21 08 f0 3e 21 08 34 40}  //weight: 1, accuracy: High
        $x_1_2 = {04 af 1c 00 04 3f 21 08 04 3f 21 08 f8}  //weight: 1, accuracy: High
        $x_1_3 = {f0 ae 1c 00 f0 3e 21 08 f0 3e 21 08}  //weight: 1, accuracy: High
        $x_1_4 = {83 c4 10 85 c0 89 c3 75 63 83 ec 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

