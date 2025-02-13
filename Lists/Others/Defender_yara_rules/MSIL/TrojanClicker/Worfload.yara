rule TrojanClicker_MSIL_Worfload_A_2147722894_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Worfload.A!bit"
        threat_id = "2147722894"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Worfload"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run" wide //weight: 1
        $x_1_2 = "bigpicturepop.com/redirect/" wide //weight: 1
        $x_1_3 = "Taskmgr" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

