rule Trojan_X97M_ShellHide_B_2147708086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:X97M/ShellHide.B"
        threat_id = "2147708086"
        type = "Trojan"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "ShellHide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Attribute VB_Name = \"NewMacros\"" ascii //weight: 1
        $x_1_2 = {2e 65 78 65 22 0d 0a 20 20 20 20 ?? ?? ?? ?? ?? 32 20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 0d 0a 20 20 20 20 43 68 44 72 69 76 65 20 28 ?? ?? ?? ?? ?? 32 29 0d 0a 20 20 20 20 43 68 44 69 72 20 28 ?? ?? ?? ?? ?? 32 29 0d 0a 20 20 20 20 ?? ?? ?? ?? ?? 33 20 3d 20 46 72 65 65 46 69 6c 65 28 29}  //weight: 1, accuracy: Low
        $x_1_3 = {46 6f 72 20 45 61 63 68 20 ?? ?? ?? ?? ?? 34 20 49 6e 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 72 61 67 72 61 70 68 73 0d 0a 20 20 20 20 20 20 20 20 44 6f 45 76 65 6e 74 73 0d 0a 20 20 20 20 20 20 20 20 20 20 20 20 ?? ?? ?? ?? ?? 31 31 20 3d 20 ?? ?? ?? ?? ?? 34 2e 52 61 6e 67 65 2e 54 65 78 74}  //weight: 1, accuracy: Low
        $x_1_4 = {32 20 3d 20 45 6e 76 69 72 6f 6e 28 22 55 53 45 52 50 52 4f 46 49 4c 45 22 29 0d 0a 20 20 20 20 43 68 44 72 69 76 65 20 28 ?? ?? ?? ?? ?? 32 29 0d 0a 20 20 20 20 43 68 44 69 72 20 28 ?? ?? ?? ?? ?? 32 29 0d 0a 20 20 20 20 ?? ?? ?? ?? ?? 37 20 3d 20 53 68 65 6c 6c 28 ?? ?? ?? ?? ?? 31 30 2c 20 76 62 48 69 64 65 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_X97M_ShellHide_C_2147712613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:X97M/ShellHide.C"
        threat_id = "2147712613"
        type = "Trojan"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "ShellHide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "= Environ(" ascii //weight: 2
        $x_2_2 = {46 6f 72 20 45 61 63 68 20 [0-140] 20 49 6e 20 41 63 74 69 76 65 44 6f 63 75 6d 65 6e 74 2e 50 61 72 61 67 72 61 70 68 73}  //weight: 2, accuracy: Low
        $x_3_3 = "= Shell(vbHH, 1)" ascii //weight: 3
        $x_2_4 = ".Range.Text" ascii //weight: 2
        $x_3_5 = {3d 20 43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-54] 28 00 28 00 28 00 28}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_X97M_ShellHide_D_2147717960_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:X97M/ShellHide.D"
        threat_id = "2147717960"
        type = "Trojan"
        platform = "X97M: Excel 97, 2000, XP, 2003, 2007, and 2010 macros"
        family = "ShellHide"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"%837432987fhf987r8dsc98%m%837432987fhf987r8dsc98%" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

