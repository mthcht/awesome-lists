rule TrojanSpy_AndroidOS_Emasol_A_2147668296_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Emasol.A"
        threat_id = "2147668296"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Emasol"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "android_asset/index.html" ascii //weight: 1
        $x_1_2 = "app-roid.com/app/rv.php?id=" ascii //weight: 1
        $x_1_3 = "mailaddress get!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

