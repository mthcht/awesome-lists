rule Trojan_MSIL_Greedy_AHB_2147975197_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Greedy.AHB!MTB"
        threat_id = "2147975197"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Greedy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "High"
    strings:
        $x_30_1 = "[DEBUG] Buscando usuarios em:" ascii //weight: 30
        $x_20_2 = "[DEBUG] Diretorio encontrado" ascii //weight: 20
        $x_10_3 = "[DEBUG] Processando usuario:" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

