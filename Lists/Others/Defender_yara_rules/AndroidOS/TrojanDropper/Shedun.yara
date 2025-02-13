rule TrojanDropper_AndroidOS_Shedun_A_2147744252_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Shedun.A!MTB"
        threat_id = "2147744252"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Shedun"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {00 12 03 21 04 6e 40 ?? ?? ?? ?? 12 03 [0-4] 6e 40 ?? ?? ?? ?? 21 03 35 31 11 00 48 03 00 01 ?? ?? ?? ?? 48 04 02 04 b7 43 8d 33 4f 03 00 01 d8 01 01 01 28 f1 0d 00 12 00 11 00}  //weight: 2, accuracy: Low
        $x_1_2 = {12 67 65 74 41 70 70 6c 69 63 61 74 69 6f 6e 49 6e 66 6f 00 09 67 65 74 41 73 73 65 74 73 00 0e 67 65 74 43 6c 61 73 73 4c 6f 61 64 65 72 00 10 67 65 74 44 65 63 6c 61 72 65 64 46 69 65 6c 64 00}  //weight: 1, accuracy: High
        $x_1_3 = "android.app.LoadedApk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

