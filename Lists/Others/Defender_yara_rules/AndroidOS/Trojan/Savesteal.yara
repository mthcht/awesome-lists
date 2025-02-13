rule Trojan_AndroidOS_Savesteal_GV_2147787171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Savesteal.GV!MTB"
        threat_id = "2147787171"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Savesteal"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "com/eternity/savedatagg/MainActivity" ascii //weight: 2
        $x_2_2 = "https://eternitypr.net/api/accounts" ascii //weight: 2
        $x_2_3 = "/Android/data/com.rtsoft.growtopia/files/save.dat" ascii //weight: 2
        $x_1_4 = "allmacs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

