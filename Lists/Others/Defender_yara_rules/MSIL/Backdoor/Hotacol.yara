rule Backdoor_MSIL_Hotacol_A_2147711703_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Hotacol.A"
        threat_id = "2147711703"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hotacol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {70 00 69 00 6e 00 67 00 ?? ?? 43 00 6c 00 6f 00 73 00 65 00 ?? ?? 52 00 65 00 73 00 74 00 61 00 72 00 74 00}  //weight: 1, accuracy: Low
        $x_1_2 = {73 00 65 00 6e 00 64 00 66 00 69 00 6c 00 65 00 ?? ?? 64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 ?? ?? 70 00 72 00 6f 00 63 00 65 00 73 00 73 00}  //weight: 1, accuracy: Low
        $x_1_3 = {46 00 69 00 6c 00 65 00 6d 00 61 00 6e 00 67 00 61 00 72 00 ?? ?? 67 00 65 00 74 00 64 00 72 00 65 00 76 00 69 00 72 00}  //weight: 1, accuracy: Low
        $x_1_4 = {67 00 65 00 74 00 61 00 6c 00 6c 00 ?? ?? 6a 00 70 00 67 00 ?? ?? 6a 00 70 00 67 00 32 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

