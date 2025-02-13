rule TrojanSpy_iPhoneOS_XcodeGhost_A_2147750359_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:iPhoneOS/XcodeGhost.A"
        threat_id = "2147750359"
        type = "TrojanSpy"
        platform = "iPhoneOS: "
        family = "XcodeGhost"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "22"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "setHidden:" ascii //weight: 1
        $x_1_2 = "Encrypt:" ascii //weight: 1
        $x_1_3 = "appendData:" ascii //weight: 1
        $x_1_4 = "openURL:" ascii //weight: 1
        $x_1_5 = "connection:didReceiveData:" ascii //weight: 1
        $x_1_6 = "connectionDidFinishLoading" ascii //weight: 1
        $x_1_7 = {4c 61 75 6e 63 68 00 52 65 73 69 67 6e}  //weight: 1, accuracy: High
        $x_1_8 = {50 4f 53 54 00 25 6c 75 00 43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68}  //weight: 1, accuracy: High
        $x_1_9 = "BundleID" ascii //weight: 1
        $x_1_10 = "Timestamp" ascii //weight: 1
        $x_1_11 = "OSVersion" ascii //weight: 1
        $x_1_12 = "DeviceType" ascii //weight: 1
        $x_1_13 = "Language" ascii //weight: 1
        $x_1_14 = "CountryCode" ascii //weight: 1
        $x_1_15 = "Wifi" ascii //weight: 1
        $x_5_16 = {77 69 66 69 00 33 47 00 74 69 6d 65 73 74 61 6d 70 00 61 70 70 00 62 75 6e 64 6c 65 00 6e 61 6d 65 00 6f 73 00 74 79 70 65 00 73 74 61 74 75 73 00 6c 61 6e 67 75 61 67 65 00 63 6f 75 6e 74 72 79 00 69 64 66 76 00 6e 65 74 77 6f 72 6b 00 76 65 72 73 69 6f 6e}  //weight: 5, accuracy: High
        $x_10_17 = "http://init.icloud-analysis.com" ascii //weight: 10
        $x_10_18 = "htps:/in.cra-lyomudg" wide //weight: 10
        $x_10_19 = "headrboypIDcnlfimvu" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 12 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 7 of ($x_1_*))) or
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            ((2 of ($x_10_*) and 1 of ($x_5_*))) or
            ((3 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_iPhoneOS_XcodeGhost_B_2147753109_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:iPhoneOS/XcodeGhost.B!MTB"
        threat_id = "2147753109"
        type = "TrojanSpy"
        platform = "iPhoneOS: "
        family = "XcodeGhost"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "f_tt.iphonespirit.com" ascii //weight: 2
        $x_1_2 = "iphonetwo.kuaiyong.com/i/i.php" ascii //weight: 1
        $x_1_3 = "com.tencent.xin" ascii //weight: 1
        $x_1_4 = "iphoneapp.kuaiyong.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

