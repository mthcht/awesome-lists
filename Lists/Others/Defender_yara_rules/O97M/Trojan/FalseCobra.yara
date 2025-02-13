rule Trojan_O97M_FalseCobra_A_2147725913_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/FalseCobra.A!dha"
        threat_id = "2147725913"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "FalseCobra"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {46 6f 72 20 [0-32] 20 3d 20 31 20 54 6f 20 4c 65 6e 28 [0-32] 29 0d 0a [0-48] 20 3d 20 [0-32] 20 26 20 43 68 72 28 41 73 63 28 4d 69 64 28 [0-32] 2c 20 [0-32] 2c 20 31 29 29 20 2d 20 [0-32] 29 0d 0a [0-16] 4e 65 78 74 20 [0-32] 0d 0a [0-48] 20 3d 20 [0-32] 0d 0a [0-16] 45 6e 64 20 46 75 6e 63 74 69 6f 6e}  //weight: 20, accuracy: Low
        $x_10_2 = {22 0d 0a 0d 0a 20 [0-32] 20 3d 20 [0-32] 20 26 20 [0-32] 20 26 20 [0-32] 20 26 20 [0-32] 20 26 20 [0-32] 20 26 20 [0-32] 20 26 20 [0-32] 20 26 20 [0-32] 20 26 20}  //weight: 10, accuracy: Low
        $x_5_3 = {53 65 74 20 [0-32] 20 3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-32] 28 [0-32] 29 29 0d 0a [0-48] 20 3d 20 [0-48] 28 22 [0-48] 22 29 0d 0a}  //weight: 5, accuracy: Low
        $x_5_4 = {2e 52 75 6e 20 [0-32] 2c 20 [0-32] 2c 20 54 72 75 65 0d 0a [0-16] 45 6e 64 20 49 66 0d 0a [0-48] 20 3d 20 22 [0-32] 22 0d 0a}  //weight: 5, accuracy: Low
        $n_30_5 = " = Application.Run(" ascii //weight: -30
        $n_30_6 = "COpen = strTemp" ascii //weight: -30
        $n_30_7 = "Select Case Target.Address" ascii //weight: -30
        $n_30_8 = "If CheckBox7.Value = True And CheckBox8.Value = True" ascii //weight: -30
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_20_*) and 2 of ($x_5_*))) or
            ((1 of ($x_20_*) and 1 of ($x_10_*))) or
            (all of ($x*))
        )
}

