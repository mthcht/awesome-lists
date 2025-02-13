rule TrojanDropper_O97M_Malgent_D_2147734399_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:O97M/Malgent.D"
        threat_id = "2147734399"
        type = "TrojanDropper"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Malgent"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {20 3d 20 28 45 72 72 2e 4e 75 6d 62 65 72 20 3d 20 30 29 0d 0a 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 1, accuracy: High
        $x_1_2 = ", Int(Rnd() * Len(" ascii //weight: 1
        $x_1_3 = "Call MsgBox(\"Something went wrong! Please contact to customer support!\", vbOKOnly, \"Error\")" ascii //weight: 1
        $x_1_4 = " = (Environ(\"temp\") & \"\\\" & " ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

