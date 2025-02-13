rule TrojanSpy_AndroidOS_Zanubis_A_2147830802_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Zanubis.A!MTB"
        threat_id = "2147830802"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Zanubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/personal/pdf/Clases/Cripto;" ascii //weight: 1
        $x_1_2 = "zanubis" ascii //weight: 1
        $x_1_3 = "pref_data_sms" ascii //weight: 1
        $x_1_4 = "getTargetPackage" ascii //weight: 1
        $x_1_5 = "str_encript" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Zanubis_B_2147850537_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Zanubis.B!MTB"
        threat_id = "2147850537"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Zanubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rutas_targets" ascii //weight: 1
        $x_1_2 = "ConServerConexiones" ascii //weight: 1
        $x_1_3 = "DelSms" ascii //weight: 1
        $x_1_4 = "onServiceConnected" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Zanubis_C_2147923680_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Zanubis.C!MTB"
        threat_id = "2147923680"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Zanubis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "valu/rano/goza" ascii //weight: 1
        $x_1_2 = "camudidofica" ascii //weight: 1
        $x_1_3 = "sifericodomu" ascii //weight: 1
        $x_1_4 = "nivalizomino" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

