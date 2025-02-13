rule TrojanSpy_AndroidOS_Adrd_A_2147643482_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Adrd.A"
        threat_id = "2147643482"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Adrd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {61 64 72 64 2e 78 69 61 78 69 61 62 2e 63 6f 6d 2f 70 69 63 2e 61 73 70 78 3f 69 6d 3d 07 00 68 74 74 70 3a 2f 2f}  //weight: 2, accuracy: Low
        $x_1_2 = "M032890500170758.mp3" ascii //weight: 1
        $x_1_3 = "go_g1_sms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_AndroidOS_Adrd_A_2147899021_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Adrd.A!MTB"
        threat_id = "2147899021"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Adrd"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "androadmgr.reefcube.biz/email.php" ascii //weight: 1
        $x_1_2 = "sendMails" ascii //weight: 1
        $x_1_3 = "com.noisysounds" ascii //weight: 1
        $x_1_4 = "arrContactsEmails" ascii //weight: 1
        $x_1_5 = "/adrd.xiaxiab.com" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

