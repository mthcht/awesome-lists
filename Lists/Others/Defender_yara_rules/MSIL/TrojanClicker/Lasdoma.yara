rule TrojanClicker_MSIL_Lasdoma_A_2147724179_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Lasdoma.A!bit"
        threat_id = "2147724179"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Lasdoma"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "EoProtectorManager.exe" ascii //weight: 1
        $x_1_2 = "laserveradedomaina.com/redirect/" wide //weight: 1
        $x_1_3 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

