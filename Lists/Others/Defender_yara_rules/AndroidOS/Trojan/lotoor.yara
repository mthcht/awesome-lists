rule Trojan_AndroidOS_lotoor_2147788174_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/lotoor.n"
        threat_id = "2147788174"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "lotoor"
        severity = "Critical"
        info = "n: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.itsblank.blankapp" ascii //weight: 1
        $x_1_2 = "DONE NO REFL" ascii //weight: 1
        $x_1_3 = "/bootloader.dex" ascii //weight: 1
        $x_1_4 = "STARTING MAIN BOOTSTRAP METHOD" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

