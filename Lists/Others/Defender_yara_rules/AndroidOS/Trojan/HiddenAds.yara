rule Trojan_AndroidOS_HiddenAds_A_2147744869_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/HiddenAds.A!MTB"
        threat_id = "2147744869"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "HiddenAds"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {21 30 23 00 1f 00 12 01 21 32 35 21 0c 00 48 02 03 01 df 02 02 ?? 8d 22 4f 02 00 01 d8 01 01 01 28 f4 11}  //weight: 2, accuracy: Low
        $x_2_2 = "res_raw.js" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_HiddenAds_H_2147829182_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/HiddenAds.H"
        threat_id = "2147829182"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "HiddenAds"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ulr =" ascii //weight: 1
        $x_1_2 = "FINSH TRUE" ascii //weight: 1
        $x_1_3 = "Have SIM card" ascii //weight: 1
        $x_1_4 = "unMuteTrackers" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

