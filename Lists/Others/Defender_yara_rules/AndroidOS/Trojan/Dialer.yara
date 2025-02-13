rule Trojan_AndroidOS_Dialer_B_2147745119_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Dialer.B!MTB"
        threat_id = "2147745119"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "youpornx.hotappsxx.com/apps/" ascii //weight: 1
        $x_1_2 = "/utils/CallDurationReceiver;" ascii //weight: 1
        $x_1_3 = "updated.apk" ascii //weight: 1
        $x_1_4 = "open_browser" ascii //weight: 1
        $x_1_5 = "/descarga.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Dialer_A_2147761367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Dialer.A!MTB"
        threat_id = "2147761367"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "Lcom/my/newproject2/SketchApplication;" ascii //weight: 2
        $x_1_2 = {74 65 6c 3a 2a 39 39 39 2a [0-2] 2a 32 2a ?? ?? ?? ?? ?? 2a [0-14] 2a 31 2a ?? 25 32 33 23}  //weight: 1, accuracy: Low
        $x_1_3 = "initializeLogic" ascii //weight: 1
        $x_1_4 = "DebugActivity.java" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Dialer_C_2147816691_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Dialer.C!MTB"
        threat_id = "2147816691"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Dialer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {54 20 07 00 1a 01 72 00 6e 20 ?? ?? 10 00 54 20 07 00 1a 01 bc 00 71 10 ?? ?? 01 00 0c 01 6e 20 ?? ?? 10 00 54 20 07 00 6e 20 ?? ?? 02 00}  //weight: 1, accuracy: Low
        $x_1_2 = "com/my/newproject2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

