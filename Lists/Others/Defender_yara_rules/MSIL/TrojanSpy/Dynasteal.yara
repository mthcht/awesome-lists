rule TrojanSpy_MSIL_Dynasteal_A_2147688693_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Dynasteal.A"
        threat_id = "2147688693"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Dynasteal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Dynasty 8.x.x Stealer Log - [" wide //weight: 1
        $x_1_2 = "Dynasty 8.x.x Keylogs - [" wide //weight: 1
        $x_1_3 = "Dynasty 8.x.x Steam, WOW, RS Stealer (Logger Edition) -- [" wide //weight: 1
        $x_1_4 = "Dynasty 8.x.x Minecraft Stealer - [" wide //weight: 1
        $x_1_5 = "Dynasty 8.x.x Notification Email - [" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

