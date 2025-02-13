rule TrojanSpy_AndroidOS_PJobRat_C_2147799283_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/PJobRat.C"
        threat_id = "2147799283"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "PJobRat"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "sgnlite" ascii //weight: 1
        $x_1_2 = "DB_REF_LS_PROTECTION" ascii //weight: 1
        $x_1_3 = "BCAppsDetail" ascii //weight: 1
        $x_1_4 = "mlocotbl" ascii //weight: 1
        $x_1_5 = "shlcmd_" ascii //weight: 1
        $x_1_6 = "sp_key_username" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

