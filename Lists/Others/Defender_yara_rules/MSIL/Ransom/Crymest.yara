rule Ransom_MSIL_Crymest_A_2147725264_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Crymest.A!bit"
        threat_id = "2147725264"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crymest"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Your file have been encrypted" wide //weight: 1
        $x_1_2 = "Taskmgr" wide //weight: 1
        $x_1_3 = {2a 00 2e 00 74 00 78 00 74 00 ?? ?? 2e 00 65 00 6e 00 63 00}  //weight: 1, accuracy: Low
        $x_1_4 = {00 45 6e 63 72 79 70 74 46 69 6c 65 73 00}  //weight: 1, accuracy: High
        $x_1_5 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

