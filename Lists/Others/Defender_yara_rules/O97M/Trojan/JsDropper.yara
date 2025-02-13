rule Trojan_O97M_JsDropper_A_2147741042_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/JsDropper.A"
        threat_id = "2147741042"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "JsDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\"\" & Chr(83) & \"he\" & \"l\" & Chr(108)" ascii //weight: 1
        $x_1_2 = "\"\" & Chr(80 + 3) & \"he\" & \"l\" & Chr(100 + 8)" ascii //weight: 1
        $x_1_3 = "Chr(32) & \"/\" & Chr(101) & \":\"" ascii //weight: 1
        $x_1_4 = "Chr(30 + 2) & \"/\" & Chr(100 + 1) & \":\"" ascii //weight: 1
        $x_1_5 = {43 68 72 28 [0-11] 29 20 26 20 43 68 72 28 [0-11] 29 20 26 20 22 72 22 20 26 20 22 69 70 22 20 26 20 22 74 22}  //weight: 1, accuracy: Low
        $x_1_6 = {43 68 72 28 [0-11] 29 20 26 20 43 68 72 28 [0-11] 29 20 26 20 22 72 22 20 26 20 22 69 70 74 22}  //weight: 1, accuracy: Low
        $x_1_7 = {22 70 70 6c 69 22 20 26 20 43 68 72 28 90 02 08 29 20 26 20 22 61 74 69 6f 6e 22}  //weight: 1, accuracy: High
        $x_1_8 = {26 20 22 70 70 22 20 26 20 22 6c 69 22 20 26 20 43 68 72 28 [0-12] 29 20 26 20 22 61 74 22 20 26 20 22 69 6f 6e 22}  //weight: 1, accuracy: Low
        $x_1_9 = {22 45 78 65 22 20 26 20 43 68 72 28 [0-15] 29 20 26 20 22 75 22 20 26 20 22 74 22 20 26 20 43 68 72 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_O97M_JsDropper_B_2147742088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/JsDropper.B"
        threat_id = "2147742088"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "JsDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {3d 20 22 53 65 74 20 [0-16] 20 3d 20 4e 65 77 20 [0-16] 20 46 6f 72 20 45 61 63 68 20 [0-16] 20 49 6e 20 [0-16] 20 57 68 69 6c 65 20 4e 6f 74 20 [0-16] 20 22}  //weight: 10, accuracy: Low
        $x_1_2 = ".AttachedTemplate.Path" ascii //weight: 1
        $x_10_3 = "& \".jse\"" ascii //weight: 10
        $x_1_4 = "WshScript.ShellExecute" ascii //weight: 1
        $x_1_5 = {4f 70 65 6e 20 [0-16] 20 46 6f 72 20 4f 75 74 70 75 74 20 41 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_JsDropper_C_2147742092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/JsDropper.C"
        threat_id = "2147742092"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "JsDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "= \"S\" & Chr(95 + 4) & \"ript\"" ascii //weight: 10
        $x_10_2 = "= Replace(ActiveDocument.FullName, \".docm\", \".~\")" ascii //weight: 10
        $x_1_3 = {50 72 69 6e 74 20 23 [0-16] 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_O97M_JsDropper_C_2147742092_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/JsDropper.C"
        threat_id = "2147742092"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "JsDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "= \"S\" & Chr(90 + 9) & \"r\" & \"ipt\"" ascii //weight: 10
        $x_10_2 = "= Replace(ActiveDocument.FullName, \".d\" & \"o\" & Chr(99) & \"m\", \".d\" & \"at\")" ascii //weight: 10
        $x_1_3 = {50 72 69 6e 74 20 23 [0-16] 2c 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 43 6f 6e 74 65 6e 74 2e 54 65 78 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

