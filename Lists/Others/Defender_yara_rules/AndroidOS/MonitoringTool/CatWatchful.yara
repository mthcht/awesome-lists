rule MonitoringTool_AndroidOS_CatWatchful_A_332685_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/CatWatchful.A!MTB"
        threat_id = "332685"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "CatWatchful"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "obtenerNombreContacto" ascii //weight: 1
        $x_1_2 = "enviarHistorialLlamadas" ascii //weight: 1
        $x_1_3 = "obtenerUltimosSms" ascii //weight: 1
        $x_1_4 = "wosc/play/dominio" ascii //weight: 1
        $x_1_5 = "Grabacion en curso" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_CatWatchful_B_346324_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/CatWatchful.B!MTB"
        threat_id = "346324"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "CatWatchful"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "swtchRecordAudio" ascii //weight: 1
        $x_1_2 = "WtspChatListElement" ascii //weight: 1
        $x_1_3 = "artefactos/ScreenCaptur" ascii //weight: 1
        $x_1_4 = "DetectaGpsOnOff" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_CatWatchful_C_456159_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/CatWatchful.C!MTB"
        threat_id = "456159"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "CatWatchful"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "Lwosc/play/WakeUp" ascii //weight: 2
        $x_2_2 = "Lwosc/play/detectores/DetectaNotificaciones" ascii //weight: 2
        $x_2_3 = "Lwosc/play/detectores/DetectaGpsOnOff" ascii //weight: 2
        $x_2_4 = "Lwosc/play/dominio" ascii //weight: 2
        $x_1_5 = "guardarListaSms" ascii //weight: 1
        $x_1_6 = "ultimoTimeStampSms" ascii //weight: 1
        $x_1_7 = "getUsrPassword&email=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

