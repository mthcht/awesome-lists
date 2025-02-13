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

