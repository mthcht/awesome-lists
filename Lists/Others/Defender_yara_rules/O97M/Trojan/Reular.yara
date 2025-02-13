rule Trojan_O97M_Reular_A_2147742306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Reular.A!MTB"
        threat_id = "2147742306"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Reular"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {3d 20 52 65 70 6c 61 63 65 28 28 22 68 74 74 70 3a 2f 2f 72 65 67 75 6c 61 72 2e 70 6b 2f 73 79 73 2f [0-21] 2e ?? ?? ?? 22 29 2c 20 22 ?? ?? ?? 22 2c 20 22 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {24 28 52 65 70 6c 61 63 65 28 [0-32] 29 29 20 26 20 22 5c 22 20 26 20 52 65 70 6c 61 63 65 28 22 66 69 6c 65 6e 61 6d 65 2e ?? ?? ?? 22 2c 20 22 ?? ?? ?? 22 2c 20 22 65 78 65 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {53 68 65 6c 6c 20 28 22 63 22 20 2b 20 22 65 22 20 2b 20 22 72 22 20 2b 20 22 74 22 20 2b 20 22 75 22 20 2b 20 22 74 22 20 2b 20 22 69 22 20 2b 20 22 6c 22 20 2b 20 22 2e 22 20 2b 20 22 65 22 20 2b 20 22 78 22 20 2b 20 22 65 22 20 26 20 22 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 22 20 26 20 68 68 20 26 20 22 20 22 20 26 20 [0-16] 29 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
        $x_1_4 = {53 68 65 6c 6c 20 28 22 66 6f 72 66 69 6c 65 73 20 2f 70 20 63 3a 5c 77 69 6e 64 6f 77 73 5c 73 79 73 74 65 6d 33 32 20 2f 6d 20 6e 6f 74 65 70 61 64 2e 65 78 65 20 2f 63 20 22 20 26 20 [0-16] 29 2c 20 76 62 48 69 64 65}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

