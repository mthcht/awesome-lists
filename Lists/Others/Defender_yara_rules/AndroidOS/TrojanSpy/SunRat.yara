rule TrojanSpy_AndroidOS_SunRat_A_2147811154_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SunRat.A!MTB"
        threat_id = "2147811154"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SunRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dataSnapshot" ascii //weight: 1
        $x_1_2 = "chatAndSpy" ascii //weight: 1
        $x_1_3 = "UploadPostTask" ascii //weight: 1
        $x_1_4 = "ttp://chatj.goldenbirdcoin.com" ascii //weight: 1
        $x_1_5 = "MonitoringTimerTask" ascii //weight: 1
        $x_1_6 = "uploadAudioFile" ascii //weight: 1
        $x_1_7 = "saveAudioOnRootStorage" ascii //weight: 1
        $x_1_8 = "SaveWhatspVoiceNotes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

