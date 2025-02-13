rule Trojan_O97M_Vulvictus_A_2147758108_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Vulvictus.A!dha"
        threat_id = "2147758108"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Vulvictus"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "echo ---------- net_user_%username% ----------  >>%temp%" ascii //weight: 2
        $x_1_2 = "---------- Version Of OS ----------" ascii //weight: 1
        $x_1_3 = "---------- echo  firewall_rule ----------" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

