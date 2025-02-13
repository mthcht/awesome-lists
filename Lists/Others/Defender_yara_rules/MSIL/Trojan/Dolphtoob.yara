rule Trojan_MSIL_Dolphtoob_A_2147706139_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Dolphtoob.A"
        threat_id = "2147706139"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dolphtoob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "U6I775B3XVykqfxRtyePbA==" wide //weight: 2
        $x_2_2 = "Dolphin Boot" wide //weight: 2
        $x_2_3 = "- Coded For Dolphin Protector" wide //weight: 2
        $x_1_4 = "/c echo [zoneTransfer]ZoneID = 2 >" wide //weight: 1
        $x_1_5 = "pchealth.exe" wide //weight: 1
        $x_1_6 = "UrlAssociations\\http\\UserChoice" wide //weight: 1
        $x_1_7 = "4hrfienz.rfk.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

