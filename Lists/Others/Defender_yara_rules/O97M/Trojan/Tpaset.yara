rule Trojan_O97M_Tpaset_A_2147735785_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Tpaset.A"
        threat_id = "2147735785"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Tpaset"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\" -NoP -NonI -W Hidden -Command \"\"Invoke-E\"" ascii //weight: 1
        $x_1_2 = "+ \"xpression $(New-Object IO.StreamReader ($(New-Ob\"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

