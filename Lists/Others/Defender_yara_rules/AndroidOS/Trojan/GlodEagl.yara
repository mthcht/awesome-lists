rule Trojan_AndroidOS_GlodEagl_B_2147914093_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/GlodEagl.B!MTB"
        threat_id = "2147914093"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "GlodEagl"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Lcom/example/trojan/netWrok" ascii //weight: 5
        $x_1_2 = "sendTelegram" ascii //weight: 1
        $x_5_3 = "Lcom/sarkuy/ui/SplashActivity" ascii //weight: 5
        $x_1_4 = "/gettask.php" ascii //weight: 1
        $x_1_5 = "/savegps.php" ascii //weight: 1
        $x_1_6 = "/recivefile.php" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

