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

rule TrojanSpy_AndroidOS_SMSAgnt_B_2147943311_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SMSAgnt.B!MTB"
        threat_id = "2147943311"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SMSAgnt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GalleryEyeUploader.kt" ascii //weight: 1
        $x_1_2 = "GalleryEyeRuntimePermissions.kt" ascii //weight: 1
        $x_1_3 = "GalleryEyeMainActivity.kt" ascii //weight: 1
        $x_1_4 = "GalleryEyeForegroundService.kt" ascii //weight: 1
        $x_1_5 = "abyssalarmy/galleryeyf/GalleryEyeUtils/GalleryEyeRuntimePermissions$grantPermissions" ascii //weight: 1
        $x_1_6 = {14 00 b7 a9 c0 5a 08 01 2b 00 72 20 e8 64 01 00 0c 0c 1a 01 54 2b 71 20 86 66 1c 00 dd 01 0b 01 38 01 05 00 de 01 0d 06 28 11 dd 01 0d 0e 39 01 0d 00 72 20 be 64 ec 00 0a 01 38 01 04 00 12 41 28 02 12 21 b6 d1 28 02}  //weight: 1, accuracy: High
        $x_1_7 = {dd 11 0b 40 38 11 0b 00 15 11 18 00 96 01 01 11 02 12 01 00 05 00 20 00 28 1b 15 11 38 00 95 11 0d 11 02 2b 01 00 05 00 20 00 39 11 10 00 72 30 bd 64 0c 01 0a 12 38 12 05 00 15 12 10 00 28 03 15 12 08 00 96 12 2b 12}  //weight: 1, accuracy: High
        $x_1_8 = {02 02 22 00 d5 b3 00 01 38 03 09 00 15 03 00 06 96 12 12 03 05 0e 23 00 28 15 15 03 00 0e b5 d3 05 0e 23 00 39 03 0f 00 72 30 bd 64 ec 0f 0a 03 38 03 05 00 15 03 00 04 28 03 15 03 00 02 96 12 12 03 d5 b3 00 02 38 03 09 00 15 03 00 30 96 12 12 03 05 0e 25 00 28 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

