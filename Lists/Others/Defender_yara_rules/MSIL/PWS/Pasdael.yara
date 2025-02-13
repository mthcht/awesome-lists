rule PWS_MSIL_Pasdael_A_2147686425_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:MSIL/Pasdael.A"
        threat_id = "2147686425"
        type = "PWS"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Pasdael"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = " Vic-Log" wide //weight: 1
        $x_1_2 = "Gespeicherte Passwoerter:" wide //weight: 1
        $x_1_3 = "\\ClientRegistry.blob" wide //weight: 1
        $x_1_4 = {02 72 01 00 00 70 72 05 00 00 70 6f ?? ?? ?? ?? 10 00 02 72 09 00 00 70 72 0d 00 00 70 6f ?? ?? ?? ?? 10 00 02 72 11 00 00 70 72 15 00 00 70 6f}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

