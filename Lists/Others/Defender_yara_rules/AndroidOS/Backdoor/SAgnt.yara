rule Backdoor_AndroidOS_SAgnt_A_2147832910_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/SAgnt.A!MTB"
        threat_id = "2147832910"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/notification_disable.php" ascii //weight: 1
        $x_1_2 = "/api/CallLog" ascii //weight: 1
        $x_1_3 = "/api/UploadDirectory" ascii //weight: 1
        $x_1_4 = "Read Keyloger" ascii //weight: 1
        $x_1_5 = "Lcom/ahrar/media" ascii //weight: 1
        $x_1_6 = "KeylogerSendStatus" ascii //weight: 1
        $x_1_7 = "SendFileServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Backdoor_AndroidOS_SAgnt_B_2147923683_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:AndroidOS/SAgnt.B!MTB"
        threat_id = "2147923683"
        type = "Backdoor"
        platform = "AndroidOS: Android operating system"
        family = "SAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/smartns/easycomp/MainActivity" ascii //weight: 1
        $x_1_2 = "FILE_SENDING_URL_FILE_NAME" ascii //weight: 1
        $x_1_3 = "/sdcard/MyRepUrlSms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

