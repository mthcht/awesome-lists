rule Trojan_AndroidOS_zanubis_A_2147830837_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/zanubis.A"
        threat_id = "2147830837"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "zanubis"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "getAccesibilidadVistaEstado" ascii //weight: 2
        $x_2_2 = "funcionConectarServer" ascii //weight: 2
        $x_2_3 = "getBloquearTelefono" ascii //weight: 2
        $x_2_4 = "EliminarNotificaciones" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

