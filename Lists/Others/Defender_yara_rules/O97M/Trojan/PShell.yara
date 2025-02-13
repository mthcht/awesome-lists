rule Trojan_O97M_PShell_E_2147731892_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/PShell.E"
        threat_id = "2147731892"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "PShell"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {20 3d 20 43 44 61 74 65 28 ?? ?? ?? ?? ?? ?? 20 2b 20 53 69 6e 28 ?? ?? ?? ?? ?? 20 2b 20 ?? ?? ?? ?? ?? 29 20 2a 20 ?? ?? ?? ?? ?? 20 2a 20 43 49 6e 74 28 ?? ?? ?? ?? ?? 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = " = \"OwerSHel" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

