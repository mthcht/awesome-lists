rule Trojan_MSIL_Noswk_PGN_2147939898_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Noswk.PGN!MTB"
        threat_id = "2147939898"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Noswk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YUhSMGNITTZMeTlvYTNWMUxtOXpjeTFqYmkxb2IyNW5hMjl1Wnk1aGJHbDVkVzVqY3k1amIyMHZSbWw0TDBacGVDNTBlSFE9" ascii //weight: 1
        $x_2_2 = "DeobfuscateString" ascii //weight: 2
        $x_2_3 = "DecodeBase64ToUrl" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

