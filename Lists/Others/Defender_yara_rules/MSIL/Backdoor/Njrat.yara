rule Backdoor_MSIL_Njrat_C_2147726104_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Njrat.C!bit"
        threat_id = "2147726104"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Njrat"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Njrat" wide //weight: 1
        $x_1_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_3 = {1f 1d 0f 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
        $x_1_4 = {1f 1d 0f 01 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

