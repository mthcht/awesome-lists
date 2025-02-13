rule Backdoor_MSIL_Flobo_2147686396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MSIL/Flobo"
        threat_id = "2147686396"
        type = "Backdoor"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Flobo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Flood Already Active" wide //weight: 1
        $x_1_2 = ":ZONE.identifier" wide //weight: 1
        $x_1_3 = "Software\\Microsoft\\Protected Storage System Provider" wide //weight: 1
        $x_1_4 = {1f 1d 12 00 1a 28 ?? 00 00 06}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

