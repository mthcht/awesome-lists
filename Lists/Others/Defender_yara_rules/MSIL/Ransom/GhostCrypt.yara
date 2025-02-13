rule Ransom_MSIL_GhostCrypt_PAA_2147809445_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/GhostCrypt.PAA!MTB"
        threat_id = "2147809445"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "GhostCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wmic shadowcopy delete" ascii //weight: 1
        $x_1_2 = "Watch-Me-Recover-Files" ascii //weight: 1
        $x_1_3 = "fuck man" ascii //weight: 1
        $x_1_4 = "killme.bat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

