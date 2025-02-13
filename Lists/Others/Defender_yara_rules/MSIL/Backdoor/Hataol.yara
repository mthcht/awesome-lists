rule Backdoor_MSIL_Hataol_A_2147717140_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Hataol.A"
        threat_id = "2147717140"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Hataol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".no-ip.biz" wide //weight: 1
        $x_1_2 = "_SKA bate" wide //weight: 1
        $x_1_3 = {52 00 65 00 73 00 74 00 61 00 72 00 74 00 ?? ?? 73 00 65 00 6e 00 64 00 66 00 69 00 6c 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {64 00 6f 00 77 00 6e 00 6c 00 6f 00 61 00 64 00 ?? ?? 6a 00 70 00 67 00}  //weight: 1, accuracy: Low
        $x_1_5 = {70 00 69 00 6e 00 67 00 ?? ?? 43 00 6c 00 6f 00 73 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

