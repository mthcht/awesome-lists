rule TrojanDropper_AndroidOS_Bankpa_A_2147744788_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:AndroidOS/Bankpa.A!MTB"
        threat_id = "2147744788"
        type = "TrojanDropper"
        platform = "AndroidOS: Android operating system"
        family = "Bankpa"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lapkpacker/ApkPackerApplication;" ascii //weight: 1
        $x_1_2 = "debugger detected" ascii //weight: 1
        $x_1_3 = "AntiEmulator" ascii //weight: 1
        $x_1_4 = "IntegrityCheck" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

