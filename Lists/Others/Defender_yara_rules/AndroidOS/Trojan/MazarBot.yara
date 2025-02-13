rule Trojan_AndroidOS_MazarBot_A_2147918411_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/MazarBot.A"
        threat_id = "2147918411"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "MazarBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "areAllVbvFieldsValid" ascii //weight: 2
        $x_2_2 = "readMessagesFromDeviceDB" ascii //weight: 2
        $x_2_3 = "makeIdSavedConfirm" ascii //weight: 2
        $x_2_4 = "BINS_WITHOUT_VBV" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

