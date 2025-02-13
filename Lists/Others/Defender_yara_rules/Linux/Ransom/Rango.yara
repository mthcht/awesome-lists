rule Ransom_Linux_Rango_A_2147837901_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Linux/Rango.A!MTB"
        threat_id = "2147837901"
        type = "Ransom"
        platform = "Linux: Linux platform"
        family = "Rango"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "main.Encrypt" ascii //weight: 1
        $x_1_2 = "LuanSilveiraSouza/rangoware/explorer.MapFiles" ascii //weight: 1
        $x_1_3 = "/rangoware/keygen.GenerateKey" ascii //weight: 1
        $x_1_4 = "filepath.Walk" ascii //weight: 1
        $x_1_5 = "dirtyLocked" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

