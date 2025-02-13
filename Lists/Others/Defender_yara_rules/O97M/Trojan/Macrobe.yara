rule Trojan_O97M_Macrobe_F_2147760907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Macrobe.F!MTB"
        threat_id = "2147760907"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Macrobe"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {52 65 70 6c 61 63 65 28 22 [0-37] 68 74 74 70 3a 2f 2f [0-3] 2e [0-3] 2e [0-3] 2e [0-3] 2f 4d 69 6e 69 70 69 6c 6c 2e 65 78 65 [0-37] 22 2c 20 22 [0-37] 22 2c 20 22 22 29}  //weight: 2, accuracy: Low
        $x_1_2 = {52 65 70 6c 61 63 65 28 22 [0-41] 53 79 73 74 65 6d 43 6f 64 65 44 6f 6d 43 6f 6d 70 69 6c 65 72 43 6f 64 65 47 65 6e 65 72 61 74 6f 72 4f 70 74 69 6f 6e 73 51 2e 65 6d 43 6f 6d 70 6f 6e 65 6e 74 4d 6f 64 65 6c 4d 65 72 67 61 62 6c 65 50 72 6f 70 65 72 74 79 41 74 74 72 69 62 75 74 65 58 78 65 22 2c 20 22 [0-41] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "CreateProcess(vbNullString" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

