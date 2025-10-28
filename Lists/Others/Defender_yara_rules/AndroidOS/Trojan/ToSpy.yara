rule Trojan_AndroidOS_ToSpy_A_2147956181_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/ToSpy.A!MTB"
        threat_id = "2147956181"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "ToSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DeviceFileHelper$fetchAllAudioFiles" ascii //weight: 1
        $x_1_2 = "DeviceFileHelper$fetchSMSFile" ascii //weight: 1
        $x_1_3 = "/worker/UploadAlarmReceiver" ascii //weight: 1
        $x_1_4 = "/worker/BackupFileWorker" ascii //weight: 1
        $x_1_5 = "/worker/SMSFileWorker" ascii //weight: 1
        $x_1_6 = "/worker/ContactsFileWorker" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

