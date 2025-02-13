rule Trojan_AndroidOS_Filecoder_C_2147741765_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Filecoder.C"
        threat_id = "2147741765"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Filecoder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "luckyseven" ascii //weight: 1
        $x_1_2 = "rich7.xyz" ascii //weight: 1
        $x_1_3 = "affected" ascii //weight: 1
        $x_1_4 = "pastebin.com" ascii //weight: 1
        $x_1_5 = "Bitcoin address copy completed" ascii //weight: 1
        $x_1_6 = "start show warning" ascii //weight: 1
        $x_1_7 = "locking file" ascii //weight: 1
        $x_1_8 = "locking photo" ascii //weight: 1
        $x_1_9 = ".seven" ascii //weight: 1
        $x_1_10 = "Ljava/lang/Thread;" ascii //weight: 1
        $x_1_11 = "Ljava/lang/Runnable;" ascii //weight: 1
        $x_1_12 = "sendMultipartTextMessage" ascii //weight: 1
        $x_1_13 = "Landroid/telephony/SmsManager;" ascii //weight: 1
        $x_1_14 = "getBtcUrl" ascii //weight: 1
        $x_1_15 = "getDecryptUrl" ascii //weight: 1
        $x_1_16 = "getPhotoPath" ascii //weight: 1
        $x_1_17 = "getInnerStoragePath" ascii //weight: 1
        $x_1_18 = "getAllWorkFile" ascii //weight: 1
        $x_1_19 = "getAllUnworkFile" ascii //weight: 1
        $x_1_20 = "generateRSAKeyPair" ascii //weight: 1
        $x_1_21 = "encryptByPublicKeyForSpilt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (14 of ($x*))
}

