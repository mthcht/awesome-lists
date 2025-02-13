rule TrojanSpy_AndroidOS_Basbanke_B_2147762213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Basbanke.B!MTB"
        threat_id = "2147762213"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "verlaietivity" ascii //weight: 1
        $x_1_2 = "_acs_onactivitynameretrieved" ascii //weight: 1
        $x_1_3 = "_addoverlay_a" ascii //weight: 1
        $x_1_4 = "com.android.packageinstaller:id/permission_allow_button" ascii //weight: 1
        $x_1_5 = "PerformGlobalAction" ascii //weight: 1
        $x_1_6 = "Les/adadda/ujd/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule TrojanSpy_AndroidOS_Basbanke_A_2147782786_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Basbanke.A"
        threat_id = "2147782786"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "RecebedorDadosBanker2" ascii //weight: 1
        $x_1_2 = "idsecurity.ini" ascii //weight: 1
        $x_1_3 = "xMenssagem_A" ascii //weight: 1
        $x_1_4 = "data=LERPIS|hehe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Basbanke_C_2147810780_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Basbanke.C"
        threat_id = "2147810780"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "xClicaXeY" ascii //weight: 1
        $x_1_2 = "Hierarchi" ascii //weight: 1
        $x_1_3 = "PuxarJanelaAtualNode" ascii //weight: 1
        $x_1_4 = "OuEscreveve" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Basbanke_D_2147825237_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Basbanke.D!MTB"
        threat_id = "2147825237"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "inject_activity" ascii //weight: 1
        $x_1_2 = "getdefaultsms_activity" ascii //weight: 1
        $x_1_3 = "PhoneSms" ascii //weight: 1
        $x_1_4 = "getpassactivity" ascii //weight: 1
        $x_1_5 = "sms_deliver" ascii //weight: 1
        $x_1_6 = "fakepin_activity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Basbanke_E_2147828148_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Basbanke.E!MTB"
        threat_id = "2147828148"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Basbanke"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fakepin_activity" ascii //weight: 1
        $x_1_2 = "getpassactivity" ascii //weight: 1
        $x_1_3 = "com.android.packageinstaller:id/permission_allow_button" ascii //weight: 1
        $x_1_4 = "inject_activity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

