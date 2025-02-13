rule TrojanDropper_AndroidOS_Rootnik_B_2147783792_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Rootnik.B!MTB"
        threat_id = "2147783792"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Rootnik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dev_root2" ascii //weight: 1
        $x_1_2 = "rooting using package" ascii //weight: 1
        $x_1_3 = "is rooted" ascii //weight: 1
        $x_1_4 = "pm install -r" ascii //weight: 1
        $x_1_5 = "update root db" ascii //weight: 1
        $x_1_6 = "push.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_AndroidOS_Rootnik_C_2147822181_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Rootnik.C!MTB"
        threat_id = "2147822181"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Rootnik"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {3b 1c a8 47 35 1c 82 46 00 28 1a d1 84 23 99 46 0a e0 23 68 4a 46 20 1c 9e 58 29 1c 42 46 3b 1c b0 47 00 28 18 d1 2e 1c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

