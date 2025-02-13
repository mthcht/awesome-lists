rule Trojan_VBA_Vigorf_CA_2147745536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:VBA/Vigorf.CA!eml"
        threat_id = "2147745536"
        type = "Trojan"
        platform = "VBA: Visual Basic for Applications scripts"
        family = "Vigorf"
        severity = "Critical"
        info = "eml: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_MACROHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {72 65 64 65 66 69 6c 65 70 72 2e 73 73 6c 62 6c 69 6e 64 61 64 6f 2e 63 6f 6d 2f [0-15] 2e 68 74 61}  //weight: 1, accuracy: Low
        $x_1_2 = {3d 20 47 65 74 4f 62 6a 65 63 74 28 22 77 69 6e 6d 67 6d 74 73 3a [0-80] 5c 72 6f 6f 74 5c 63 69 6d 76 32 22 29}  //weight: 1, accuracy: Low
        $x_1_3 = "= objWMIService.Get(\"Win32_Process\")" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

