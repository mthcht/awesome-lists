rule Trojan_AndroidOS_Virtualinst_A_2147899824_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Virtualinst.A"
        threat_id = "2147899824"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Virtualinst"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "unzipFile+,tempDir=" ascii //weight: 1
        $x_1_2 = "update soFiles=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

