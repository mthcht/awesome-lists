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

rule Trojan_Linux_Morcut_B_2147947803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Linux/Morcut.B!MTB"
        threat_id = "2147947803"
        type = "Trojan"
        platform = "Linux: Linux platform"
        family = "Morcut"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {89 c2 b8 00 00 00 00 8b 8d d0 fd ff ff 89 d7 f2 ae 89 c8 f7 d0 8d 50 ff b8 00 04 00 00 89 c1 29 d1 89 ca 8b 85 e4 fd ff ff 89 44 24 14 8b 85 e0 fd ff ff 89 44 24 10 8b 85 ec fd ff ff 89 44 24 0c 89 5c 24 08 89 54 24 04 8b 85 f0 fd ff ff 89 04 24}  //weight: 1, accuracy: High
        $x_1_2 = {8b 85 1c ff ff ff 89 c1 bb 00 00 00 00 8b 85 14 ff ff ff ba 00 00 00 00 89 df 0f af f8 89 d6 0f af f1 01 fe f7 e1 8d 0c 16 89 ca 0f ac d0 1e c1 ea 1e 89 c2 8b 85 04 ff ff ff 89 90 8c 01 00 00 8b 85 24 ff ff ff 89 c1 bb 00 00 00 00 8b 85 14 ff ff ff ba 00 00 00 00 89 df 0f af f8 89 d6 0f af f1 01 fe}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

