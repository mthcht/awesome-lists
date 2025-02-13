rule Trojan_AndroidOS_FakeSMS_A_2147831442_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeSMS.A!MTB"
        threat_id = "2147831442"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeSMS"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {12 03 71 00 0d 00 00 00 0c 00 22 01 06 00 1a 02 ?? 00 70 20 05 00 21 00 71 40 03 00 36 31 0c 04 22 01 06 00 1a 02 ?? 00 70 20 05 00 21 00 71 40 03 00 36 31 0c 05 12 02 07 71 07 83 74 06 0e 00 00 00 0e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_FakeSMS_A_2147842752_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/FakeSMS.A"
        threat_id = "2147842752"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "FakeSMS"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "s_msofts" ascii //weight: 2
        $x_2_2 = "nsev375" ascii //weight: 2
        $x_2_3 = "afonPrice" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

