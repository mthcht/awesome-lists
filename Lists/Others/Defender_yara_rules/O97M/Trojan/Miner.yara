rule Trojan_O97M_Miner_F_2147728500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Miner.F"
        threat_id = "2147728500"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Miner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://pastebin.com/raw/sxPYz7fT" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

