rule Ransom_MSIL_GhostHacker_YAA_2147911748_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/GhostHacker.YAA!MTB"
        threat_id = "2147911748"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostHacker"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "way to recover your files" ascii //weight: 1
        $x_1_2 = "without our decryption service" ascii //weight: 1
        $x_1_3 = "Files Are Encrypted ,NoCry" ascii //weight: 1
        $x_1_4 = "NoCry.My.Resources" ascii //weight: 1
        $x_1_5 = "get_bitcoin" ascii //weight: 1
        $x_1_6 = "VIRTUAL" wide //weight: 1
        $x_1_7 = "vmware" wide //weight: 1
        $x_1_8 = "VirtualBox" wide //weight: 1
        $x_1_9 = "Decryption Key" wide //weight: 1
        $x_1_10 = "Contact Me On My Email" wide //weight: 1
        $x_1_11 = "GhostHacker_ReadMe.html" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

