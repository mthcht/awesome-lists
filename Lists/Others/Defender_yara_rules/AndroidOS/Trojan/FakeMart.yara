rule Trojan_AndroidOS_FakeMart_A_2147811836_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeMart.A!MTB"
        threat_id = "2147811836"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeMart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "deleteSMS" ascii //weight: 1
        $x_1_2 = "DownloadFromUrlV2" ascii //weight: 1
        $x_1_3 = "UploadTest" ascii //weight: 1
        $x_1_4 = "SMSSendFunction" ascii //weight: 1
        $x_1_5 = "mathissarox.myartsonline.com/momitojuli.php" ascii //weight: 1
        $x_1_6 = "Lcom/android/blackmarket" ascii //weight: 1
        $x_1_7 = "MuteSound" ascii //weight: 1
        $x_1_8 = "9127" ascii //weight: 1
        $x_1_9 = "BD MULTIMEDIA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

