rule Trojan_O97M_Cryxos_AAE_2147751649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:O97M/Cryxos.AAE!MTB"
        threat_id = "2147751649"
        type = "Trojan"
        platform = "O97M: Office 97, 2000, XP, 2003, 2007, and 2010 macros - those that affect Word, Excel, and PowerPoint"
        family = "Cryxos"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 72 65 61 74 65 4f 62 6a 65 63 74 28 [0-15] 28 22 [0-5] 57 [0-5] 53 [0-5] 63 [0-5] 72 [0-5] 69 [0-5] 70 [0-5] 74 [0-5] 22 20 26 20 22 [0-5] 2e 53 [0-5] 68 [0-5] 65 6c [0-5] 6c 22 29}  //weight: 1, accuracy: Low
        $x_1_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 2e 53 74 61 72 74 75 70 50 61 74 68 20 26 20 [0-15] 28 22 [0-47] 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = {26 20 43 68 72 28 [0-15] 20 2b 20 [0-9] 29 20 26 20 [0-15] 20 26 20 43 68 72 28 [0-15] 20 2b 20 [0-9] 29 6f 00 28 22 [0-5] 65 [0-5] 78 [0-5] 70 [0-5] 6c [0-5] 6f [0-5] 72 [0-5] 65 [0-5] 72 [0-5] 2e [0-5] 65 [0-5] 78 [0-5] 65 [0-5] 22 29}  //weight: 1, accuracy: Low
        $x_1_4 = {52 65 70 6c 61 63 65 28 [0-15] 2c 20 22 [0-5] 22 2c 20 22 22 29}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

