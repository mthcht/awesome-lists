rule TrojanSpy_AndroidOS_Vdloader_A_2147661078_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Vdloader.A"
        threat_id = "2147661078"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Vdloader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "X_PHONE_INFO" ascii //weight: 1
        $x_1_2 = "ad must be gone," ascii //weight: 1
        $x_1_3 = "cn.neogou" ascii //weight: 1
        $x_1_4 = "AdActivity is closing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

