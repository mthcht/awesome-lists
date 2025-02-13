rule Trojan_O97M_BlueSky_A_2147735864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/BlueSky.A"
        threat_id = "2147735864"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "BlueSky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {63 6f 70 79 20 2f 59 20 [0-48] 63 65 72 74 75 74 69 6c 2e 65 78 65 20 25 54 45 4d 50 25 5c 63 74 2e 65 78 65 20 26 26 20 63 64 20 2f 64 20 25 54 45 4d 50 25 20 26 26 20 63 74 20 2d 75 72 6c 63 61 63 68 65 20 2d 73 70 6c 69 74 20 2d 66 20 [0-48] 20 31 2e 62 61 74 20 26 26 20 64 65 6c 20 2f 66 20 2f 71}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 43 68 72 28 26 ?? ?? ?? 29 20 26 20 43 68 72 28 26 ?? ?? ?? 29 20 26 20 43 68 72 28 26 ?? ?? ?? 29 20 26 20 43 68 72 28 26 ?? ?? ?? 29 20 26 20 43 68 72 28 26 ?? ?? ?? 29 20 26 20 43 68 72 28 26 ?? ?? ?? 29 20 26 20 43 68 72 28 26 ?? ?? ?? 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

