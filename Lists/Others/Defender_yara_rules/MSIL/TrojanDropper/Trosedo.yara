rule TrojanDropper_MSIL_Trosedo_A_2147690036_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:MSIL/Trosedo.A"
        threat_id = "2147690036"
        type = "TrojanDropper"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Trosedo"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\" wide //weight: 1
        $x_1_2 = "Microsoft_Band.vbs" wide //weight: 1
        $x_1_3 = "Microsoft_Bax" wide //weight: 1
        $x_1_4 = "Game-Over.exe" ascii //weight: 1
        $x_1_5 = "Dim WBmVOEfqySNDvidR" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

