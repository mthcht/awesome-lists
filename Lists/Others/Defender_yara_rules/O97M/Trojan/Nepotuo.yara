rule Trojan_O97M_Nepotuo_A_2147760287_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Nepotuo.A!MTB"
        threat_id = "2147760287"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Nepotuo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {46 6f 72 20 [0-8] 20 3d 20 31 20 54 6f 20 55 42 6f 75 6e 64 28 [0-16] 49 66 20 49 73 4e 75 6d 65 72 69 63 28 [0-20] 29 20 54 68 65 6e}  //weight: 1, accuracy: Low
        $x_1_2 = {20 3d 20 4c 65 6e 28 [0-8] 29 20 2b 20 31 20 54 68 65 6e 20 49 66 20 [0-8] 20 3e 3d 20 4c 65 6e 28 [0-8] 29 20 54 68 65 6e 20 [0-8] 20 3d 20 31 20 45 6c 73 65 20 [0-8] 20 3d 20 [0-8] 20 2b 20 31 3a}  //weight: 1, accuracy: Low
        $x_1_3 = {2d 20 41 73 63 28 4d 69 64 28 [0-8] 2c 20 [0-8] 2c 20 31 29 29 20 2b 20 33 32 3a 20 [0-8] 20 3d 20 [0-8] 20 2b 20 31 3a 20 [0-8] 20 3d 20 [0-8] 20 2b 20 43 68 72 57 28}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

