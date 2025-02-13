rule Trojan_AndroidOS_Clipper_A_2147783305_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Clipper.A"
        threat_id = "2147783305"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Clipper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lclipper/abcchannelmc/ru/clipperreborn" ascii //weight: 1
        $x_1_2 = "attach.php?log&wallet=" ascii //weight: 1
        $x_1_3 = "Getted wallet" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Clipper_B_2147783306_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Clipper.B"
        threat_id = "2147783306"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Clipper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "**From Meta Mask App**" ascii //weight: 1
        $x_1_2 = "**Restore Account**" ascii //weight: 1
        $x_1_3 = "acc_idj" ascii //weight: 1
        $x_1_4 = "metamask/Util/ClipboardMonitorService" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Clipper_A_2147899649_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Clipper.A!MTB"
        threat_id = "2147899649"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Clipper"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/ImageUploader" ascii //weight: 1
        $x_1_2 = "WearReplyReceiver" ascii //weight: 1
        $x_1_3 = "archiveHidden" ascii //weight: 1
        $x_1_4 = "btcAddress" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

