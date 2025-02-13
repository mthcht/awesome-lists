rule Trojan_O97M_Dridex_AL_2147770223_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Dridex.AL!MTB"
        threat_id = "2147770223"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 22 3d 22 20 26 20 52 65 70 6c 61 63 65 28 [0-3] 2c 20 22 3f 22 2c 20 [0-15] 28 53 70 6c 69 74 28 [0-15] 28 30 29 2c 20 [0-15] 28 [0-15] 29 29 29 29}  //weight: 1, accuracy: Low
        $x_1_2 = {28 52 75 6e 28 22 22 20 2b 20 [0-15] 20 26 20 22 [0-15] 22 29 29}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 20 53 70 6c 69 74 28 [0-3] 2c 20 22 21 22 29 3a 20 [0-3] 20 3d 20 53 70 6c 69 74 28 [0-3] 28 [0-3] 29 2c 20 [0-15] 28 [0-15] 29 29 0d 0a 46 6f 72 20 45 61 63 68 20 56 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {46 6f 72 20 45 61 63 68 20 [0-3] 20 49 6e 20 42 76 0d 0a [0-4] 20 3d 20 01 20 2b 20 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Dridex_SM_2147788192_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Dridex.SM!MTB"
        threat_id = "2147788192"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "p = Len(dg) \\ 2" ascii //weight: 1
        $x_1_2 = "For mh = 1 To p" ascii //weight: 1
        $x_1_3 = "e = e & Mid(dg, mh, 1) & Mid(dg, mh + p, 1)" ascii //weight: 1
        $x_1_4 = {45 78 63 65 6c 34 4d 61 63 72 6f 53 68 65 65 74 73 2e 41 64 64 28 42 65 66 6f 72 65 3a 3d 57 6f 72 6b 73 68 65 65 74 73 28 28 [0-5] 29 29 29 2e 4e 61 6d 65 20 3d 20 22 53 73 68 65 65 74 22}  //weight: 1, accuracy: Low
        $x_1_5 = "pl = \"htt\"" ascii //weight: 1
        $x_1_6 = "lt_go = pl & \"ps://\" & tg_Tan(\"\" & a, \"K\", \".\")" ascii //weight: 1
        $x_1_7 = "a = tg_Tan(\"\" & pic_vol_chat(Split(siu_summer(siu_summer(Cells(159, 5)))))(1), \"\" & sim_S, \"/\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_O97M_Dridex_RK_2147796196_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Dridex.RK!MTB"
        threat_id = "2147796196"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Dridex"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Function mestil(ak As String, tk As String, mk As String)" ascii //weight: 1
        $x_1_2 = "mestil = Replace(ak, tk, mk)" ascii //weight: 1
        $x_1_3 = "Function Top_engeen()" ascii //weight: 1
        $x_1_4 = "a = mestil(\"\" & N_lio(Split(sin_and_tg(sin_and_tg(Cells(77, 7)))))(1), \"C\", \"/\")" ascii //weight: 1
        $x_1_5 = "Top_engeen = mestil(\"\" & a, \"A\", \".\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

