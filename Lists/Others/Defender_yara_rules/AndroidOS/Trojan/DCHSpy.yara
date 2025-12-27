rule Trojan_AndroidOS_DCHSpy_A_2147947452_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/DCHSpy.A!MTB"
        threat_id = "2147947452"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "DCHSpy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/matrix/ctor/CameraFile/CameraFile" ascii //weight: 1
        $x_1_2 = "Lcom/matrix/ctor/WhatsAppFile/WhatsAppFile" ascii //weight: 1
        $x_1_3 = "/ctor/RecordingsFile/RecordingsFile" ascii //weight: 1
        $x_1_4 = "/db/command/CommandQueries" ascii //weight: 1
        $x_1_5 = "Lcom/sftp_uploader/traveler/SFTPProgressMonitor" ascii //weight: 1
        $x_1_6 = "ActionDownloadServerUpdate" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

