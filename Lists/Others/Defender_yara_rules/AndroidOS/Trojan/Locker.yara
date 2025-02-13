rule Trojan_AndroidOS_Locker_RA_2147744613_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Locker.RA!MSR"
        threat_id = "2147744613"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Locker"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "lock/Lock1Service" ascii //weight: 1
        $x_1_2 = "protector/KeepLiveActivity" ascii //weight: 1
        $x_1_3 = "protector/AliveJob1Service" ascii //weight: 1
        $x_1_4 = "/payload.apk" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Locker_RB_2147745245_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Locker.RB!MSR"
        threat_id = "2147745245"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Locker"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {35 23 15 00 48 05 07 03 94 06 04 00 71 10 ?? ?? 06 00 0a 06 48 06 08 06 b7 65 8d 55 4f 05 01 04 d8 04 04 01 d8 03 03 01 28 ec}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Locker_A_2147753792_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Locker.A"
        threat_id = "2147753792"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Locker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "privet" ascii //weight: 2
        $x_2_2 = "is_imunnity" ascii //weight: 2
        $x_2_3 = "393838" ascii //weight: 2
        $x_2_4 = "locker_immunity" ascii //weight: 2
        $x_1_5 = "force-locked" ascii //weight: 1
        $x_1_6 = "Start unblocked process!" ascii //weight: 1
        $x_1_7 = "save_message_history" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_2_*) and 3 of ($x_1_*))) or
            ((4 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_Locker_A_2147753792_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Locker.A"
        threat_id = "2147753792"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Locker"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_3_1 = "Lcom/moli/lock/lock" ascii //weight: 3
        $x_1_2 = "Lcom/moli/lock/BootBroadcastReceiver" ascii //weight: 1
        $x_1_3 = "Landroid/view/WindowManager$LayoutParams" ascii //weight: 1
        $x_1_4 = "com.aide.runtime.VIEW_LOGCAT_ENTRY" ascii //weight: 1
        $x_1_5 = "addView" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

