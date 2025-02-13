rule TrojanSpy_MSIL_Blat_A_2147657223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Blat.A"
        threat_id = "2147657223"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Blat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "moc.liamg@oirettalb" wide //weight: 1
        $x_1_2 = "=== Cyber-Shark ===" wide //weight: 1
        $x_1_3 = "kbHook" ascii //weight: 1
        $x_1_4 = "===== Stealers =====" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

