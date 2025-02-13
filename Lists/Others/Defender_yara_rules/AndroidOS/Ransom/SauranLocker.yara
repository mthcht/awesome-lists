rule Ransom_AndroidOS_SauranLocker_A_2147783396_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:AndroidOS/SauranLocker.A"
        threat_id = "2147783396"
        type = "Ransom"
        platform = "AndroidOS: Android operating system"
        family = "SauranLocker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".encrypted" ascii //weight: 1
        $x_1_2 = "{{WALLET}}" ascii //weight: 1
        $x_1_3 = "/gateway/attach.php?uid=" ascii //weight: 1
        $x_1_4 = {4c 63 6f 6d 2f [0-64] 2f [0-64] 2f 4c 6f 63 6b 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

