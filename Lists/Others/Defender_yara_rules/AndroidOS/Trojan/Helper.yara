rule Trojan_AndroidOS_Helper_B_2147795265_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Helper.B"
        threat_id = "2147795265"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Helper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "spyOnPhoneState" ascii //weight: 2
        $x_2_2 = "tryWakeOnPackage" ascii //weight: 2
        $x_2_3 = "updatePreinstallApkInstalledReportStatus" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

