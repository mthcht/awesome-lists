rule TrojanSpy_AndroidOS_Dracarys_A_2147829149_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Dracarys.A!MTB"
        threat_id = "2147829149"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Dracarys"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "takeBackPicture" ascii //weight: 1
        $x_1_2 = "cameraExecService" ascii //weight: 1
        $x_1_3 = "PhoneMessageReportWorker" ascii //weight: 1
        $x_1_4 = "ContactInfoGatherer" ascii //weight: 1
        $x_1_5 = "dracarys" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule TrojanSpy_AndroidOS_Dracarys_B_2147829223_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Dracarys.B"
        threat_id = "2147829223"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Dracarys"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AudioRecordingUpload" ascii //weight: 1
        $x_1_2 = "DracarysReceiver" ascii //weight: 1
        $x_1_3 = ".wnk_rec" ascii //weight: 1
        $x_1_4 = "%s/%s/report/contacts" ascii //weight: 1
        $x_1_5 = ".audio_mon" ascii //weight: 1
        $x_1_6 = "CallLogReportWorker" ascii //weight: 1
        $x_1_7 = "SYNC_PRIVATE_FILES_URL" ascii //weight: 1
        $x_1_8 = "REQUEST_HEARTBEAT_URL" ascii //weight: 1
        $x_1_9 = "AppInfoGatherer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

