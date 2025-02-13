rule MonitoringTool_AndroidOS_MeuSPY_A_301086_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MeuSPY.A!MTB"
        threat_id = "301086"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MeuSPY"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ReceiverTela" ascii //weight: 1
        $x_1_2 = "ProcessarVideoOff" ascii //weight: 1
        $x_1_3 = "LVideoActivity" ascii //weight: 1
        $x_1_4 = "GravarChamada" ascii //weight: 1
        $x_1_5 = "CameraFinaliza" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_MeuSPY_A_301086_1
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/MeuSPY.A!MTB"
        threat_id = "301086"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "MeuSPY"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "MeuSPY" ascii //weight: 5
        $x_1_2 = "AudioRecorderCall" ascii //weight: 1
        $x_1_3 = "sms.txt" ascii //weight: 1
        $x_1_4 = "telefone.php?id=" ascii //weight: 1
        $x_1_5 = "uploadvideosoff.php" ascii //weight: 1
        $x_1_6 = "uploadcontato.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

