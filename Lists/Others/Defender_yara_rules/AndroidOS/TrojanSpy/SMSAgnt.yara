rule TrojanSpy_AndroidOS_SMSAgnt_A_2147842816_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSAgnt.A!MTB"
        threat_id = "2147842816"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "abyssalarmy/galleryeye/GalleryEyeUi" ascii //weight: 1
        $x_1_2 = "AUTOFILL_HINT_CREDIT_CARD_SECURITY_CODE" ascii //weight: 1
        $x_1_3 = "generateSmsOtpHintForCharacterPosition" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

