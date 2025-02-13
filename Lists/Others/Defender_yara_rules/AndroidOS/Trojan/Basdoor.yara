rule Trojan_AndroidOS_Basdoor_A_2147844101_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Basdoor.A"
        threat_id = "2147844101"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Basdoor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "/up_file2.php" ascii //weight: 2
        $x_2_2 = "&sendsms=" ascii //weight: 2
        $x_2_3 = "&action=blist" ascii //weight: 2
        $x_2_4 = "smbomber" ascii //weight: 2
        $x_2_5 = "&adminn=" ascii //weight: 2
        $x_2_6 = "&action=allapp" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

