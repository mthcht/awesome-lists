rule Trojan_AndroidOS_SpyGlitch_AA_2147974280_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyGlitch.AA!AMTB"
        threat_id = "2147974280"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyGlitch"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "14"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "post_a11y_permissions" ascii //weight: 2
        $x_2_2 = "hidden_win_" ascii //weight: 2
        $x_2_3 = "com.system.core.action.RECONNECT_C2" ascii //weight: 2
        $x_2_4 = "screen reader dump OOM" ascii //weight: 2
        $x_2_5 = "keylog_store.txt" ascii //weight: 2
        $x_2_6 = "keyguard" ascii //weight: 2
        $x_2_7 = "start_keylogger" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

