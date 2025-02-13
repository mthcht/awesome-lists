rule TrojanSpy_AndroidOS_Vmvol_A_2147766258_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Vmvol.A!MTB"
        threat_id = "2147766258"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Vmvol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "updateRemoteSmsStatus" ascii //weight: 1
        $x_1_2 = "uploadContacts" ascii //weight: 1
        $x_1_3 = "readSimContact" ascii //weight: 1
        $x_1_4 = "WIRETAP_PKGNAME" ascii //weight: 1
        $x_1_5 = "MonitorInstalled" ascii //weight: 1
        $x_1_6 = "REQUEST_CODE_INSTALL_APK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_AndroidOS_Vmvol_A_2147766258_1
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Vmvol.A!MTB"
        threat_id = "2147766258"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Vmvol"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/uploadSms.htm" ascii //weight: 1
        $x_1_2 = "/uploadAlbum.htm" ascii //weight: 1
        $x_1_3 = "/uploadContact.htm" ascii //weight: 1
        $x_1_4 = "/AutoRunReceiver;" ascii //weight: 1
        $x_1_5 = "isUploadEnvironmentRecord" ascii //weight: 1
        $x_1_6 = "setUploadCalllog" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

