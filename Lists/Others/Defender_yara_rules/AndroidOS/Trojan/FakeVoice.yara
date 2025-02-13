rule Trojan_AndroidOS_FakeVoice_A_2147653691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeVoice.A"
        threat_id = "2147653691"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeVoice"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PICK_CONTACT" ascii //weight: 1
        $x_1_2 = "error_israel" ascii //weight: 1
        $x_1_3 = "price_title" ascii //weight: 1
        $x_1_4 = "VoiceChange/VoiceChangeIL/MainActivity" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

