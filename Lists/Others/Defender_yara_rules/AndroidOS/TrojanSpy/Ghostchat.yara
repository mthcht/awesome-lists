rule TrojanSpy_AndroidOS_Ghostchat_AMTB_2147962356_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Ghostchat!AMTB"
        threat_id = "2147962356"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Ghostchat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "startDataUpload" ascii //weight: 1
        $x_1_2 = "scheduleRepeatingUpload" ascii //weight: 1
        $x_2_3 = "hitpak.org" ascii //weight: 2
        $x_2_4 = "comdatingbatchchatappChatActivity" ascii //weight: 2
        $x_1_5 = "scanAndUploadNewImages" ascii //weight: 1
        $x_2_6 = "uploadContacts" ascii //weight: 2
        $x_1_7 = "starttracking" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            ((2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((3 of ($x_2_*))) or
            (all of ($x*))
        )
}

