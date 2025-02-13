rule TrojanSpy_AndroidOS_Rafel_A_2147809080_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Rafel.A"
        threat_id = "2147809080"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Rafel"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "add_victim_device" ascii //weight: 1
        $x_1_2 = "rehber_oku" ascii //weight: 1
        $x_1_3 = "LockTheScreen" ascii //weight: 1
        $x_1_4 = "get_screenshot" ascii //weight: 1
        $x_1_5 = "upload_file_nm" ascii //weight: 1
        $x_1_6 = "swagkarnaloveshandeercel" ascii //weight: 1
        $x_1_7 = "brld_" ascii //weight: 1
        $x_1_8 = "Your files have been encripted" ascii //weight: 1
        $x_1_9 = "Rafel-Rat-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

