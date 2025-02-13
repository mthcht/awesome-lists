rule MonitoringTool_AndroidOS_Anfur_A_347828_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Anfur.A!MTB"
        threat_id = "347828"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Anfur"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "br.com.maceda.android.antifurtow" ascii //weight: 1
        $x_1_2 = "enviou_localizacao_gps" ascii //weight: 1
        $x_1_3 = "enviou_localizacao_rede" ascii //weight: 1
        $x_1_4 = "DesinstalarActivity" ascii //weight: 1
        $x_1_5 = "josiasmaceda@gmail.com" ascii //weight: 1
        $x_1_6 = "atualizarEmailNoServidor" ascii //weight: 1
        $x_1_7 = "naoSuportaAtivacaoGPS" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

