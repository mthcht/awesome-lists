rule Trojan_AndroidOS_RootSmart_A_2147782425_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/RootSmart.A!MTB"
        threat_id = "2147782425"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "RootSmart"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "fake_package_name" ascii //weight: 1
        $x_1_2 = "DekviceAdminAddActivitoy" ascii //weight: 1
        $x_1_3 = "FakkeLauncher" ascii //weight: 1
        $x_1_4 = "exploit_once" ascii //weight: 1
        $x_1_5 = "ApkpInstallActivitoy" ascii //weight: 1
        $x_1_6 = "BokotReceiveor" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

