rule PWS_MSIL_Cyborg_A_2147696218_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Cyborg.A"
        threat_id = "2147696218"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cyborg"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Passwords recovered from Cyborg v" wide //weight: 1
        $x_1_2 = ":-:-: Log from" wide //weight: 1
        $x_1_3 = ":-:-: Clipboard Text History from" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

