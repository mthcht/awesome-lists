rule Ransom_MSIL_NitroCrypt_MK_2147806049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/NitroCrypt.MK!MTB"
        threat_id = "2147806049"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "NitroCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Todos sus documentos importantes se han bloqueado y se han cifrado con AES" ascii //weight: 1
        $x_1_2 = "Oh, no! Sus archivos se han cifrado" ascii //weight: 1
        $x_1_3 = "Iniciando el cifrado de archivos" ascii //weight: 1
        $x_1_4 = "mero total de archivos cifrados:" ascii //weight: 1
        $x_1_5 = "mo obtengo la clave de descifrado?" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

