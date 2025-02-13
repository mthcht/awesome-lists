rule Adware_AndroidOS_Peterhodkinsoner_A_328898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Adware:AndroidOS/Peterhodkinsoner.A"
        threat_id = "328898"
        type = "Adware"
        platform = "AndroidOS: Android operating system"
        family = "Peterhodkinsoner"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "peterhodkinsoner" ascii //weight: 2
        $x_2_2 = "LgMNBw0HAgQVUwYYBw9BHhEEF1YJEhISQxcVUwgSAgUVUwsZBlYREhYDTQ==" ascii //weight: 2
        $x_2_3 = "LhcNFQsFDhMFUwcbDAUEUxQWGhoOEgBXDxMPFBAfQxkHU1VZ" ascii //weight: 2
        $x_1_4 = "LhcVEAwSEVgQBgsDBiQEAwgWABMMFgoDSxoIBwEFAhpI" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

