rule TrojanSpy_MSIL_Crime_B_2147658180_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Crime.B"
        threat_id = "2147658180"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Crime"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Passwort:" wide //weight: 5
        $x_1_2 = "Stealer" wide //weight: 1
        $x_1_3 = "FileZilla\\recentservers.xml" wide //weight: 1
        $x_1_4 = "GetPidgin" ascii //weight: 1
        $x_1_5 = "GetSteamUsername" ascii //weight: 1
        $x_1_6 = "get_Computer" ascii //weight: 1
        $x_1_7 = "get_WebServices" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

