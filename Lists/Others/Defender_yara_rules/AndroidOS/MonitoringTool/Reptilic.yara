rule MonitoringTool_AndroidOS_Reptilic_A_301090_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Reptilic.A!MTB"
        threat_id = "301090"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Reptilic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "FakeActivity" ascii //weight: 1
        $x_1_2 = "send_media_only_wifi" ascii //weight: 1
        $x_1_3 = "vipfile.uz/fsfl/8M99iHwxwowNqQr" ascii //weight: 1
        $x_1_4 = "sms_code_word" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule MonitoringTool_AndroidOS_Reptilic_AT_322244_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Reptilic.AT!MTB"
        threat_id = "322244"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Reptilic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "CallRecordActivity" ascii //weight: 1
        $x_1_2 = "net.delphiboardlayer.androidcoreapp" ascii //weight: 1
        $x_1_3 = "AddDeviceActivity" ascii //weight: 1
        $x_1_4 = "AddInterceptionPhotoPathActivity" ascii //weight: 1
        $x_1_5 = "AddInterceptionAudioPathActivity" ascii //weight: 1
        $x_1_6 = "FakeActivity" ascii //weight: 1
        $x_1_7 = "FirstStartWizardActivity" ascii //weight: 1
        $x_1_8 = "interception_media_whatsapp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

rule MonitoringTool_AndroidOS_Reptilic_B_349465_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Reptilic.B!MTB"
        threat_id = "349465"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Reptilic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "yc/sysupd/client" ascii //weight: 1
        $x_1_2 = "android_client_version.php" ascii //weight: 1
        $x_1_3 = "FakeActivity" ascii //weight: 1
        $x_1_4 = "cmVwdGlsaWN1cy5uZXQ=" ascii //weight: 1
        $x_1_5 = "read_browser_history" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule MonitoringTool_AndroidOS_Reptilic_C_361802_0
{
    meta:
        author = "defender2yara"
        detection_name = "MonitoringTool:AndroidOS/Reptilic.C!MTB"
        threat_id = "361802"
        type = "MonitoringTool"
        platform = "AndroidOS: Android operating system"
        family = "Reptilic"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hideUnhideApp" ascii //weight: 1
        $x_1_2 = "send_on_change_sim" ascii //weight: 1
        $x_5_3 = "net/vkurhandler/FakeActivity" ascii //weight: 5
        $x_1_4 = "intercept_added_contact" ascii //weight: 1
        $x_1_5 = "AddInterceptionAudioPathActivity" ascii //weight: 1
        $x_1_6 = "record_env_after_end_call" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

