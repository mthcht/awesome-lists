rule Ransom_MSIL_ArcbornCrypt_PA_2147808179_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/ArcbornCrypt.PA!MTB"
        threat_id = "2147808179"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "ArcbornCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "taskmgr" wide //weight: 1
        $x_1_2 = "SalbaelhNccPdQAemOeW" wide //weight: 1
        $x_1_3 = {5c 41 72 63 61 6e 65 2d 52 65 62 6f 72 6e 5c [0-16] 5c 41 72 63 61 6e 65 2d 52 65 62 6f 72 6e 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

