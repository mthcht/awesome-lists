rule Trojan_O97M_Krapame_A_2147733844_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Krapame.A"
        threat_id = "2147733844"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Krapame"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "microsoft_payload_1 = tmp_dir + \"\\\" & rand_name & \".exe.1\"" ascii //weight: 1
        $x_1_2 = "a.WriteLine (\"@start /min powe\" & Chr(114) & \"sh\" & Chr(101) & \"ll.exe \"" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

