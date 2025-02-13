rule TrojanSpy_AndroidOS_Puxis_AS_2147781672_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/Puxis.AS!MTB"
        threat_id = "2147781672"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "Puxis"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "pref_allow_sms_traffic_out" ascii //weight: 1
        $x_1_2 = {63 6f 6d 2e 67 6f 6f 67 6c 65 2e [0-18] 41 43 43 45 53 53 5f 53 45 43 52 45 54 53}  //weight: 1, accuracy: Low
        $x_1_3 = {2f 63 6f 6d 2f 67 6f 6f 67 6c 65 [0-6] 70 68 6f 6e 65 6e 75 6d 62 65 72 73 2f 64 61 74 61 2f 50 68 6f 6e 65 4e 75 6d 62 65 72 4d 65 74 61 64 61 74 61 50 72 6f 74 6f}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 63 6f 6d 2f 67 6f 6f 67 6c 65 [0-18] 42 6c 61 63 6b 41 63 74 69 76 69 74 79}  //weight: 1, accuracy: Low
        $x_1_5 = "tr/servlets/mms" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

