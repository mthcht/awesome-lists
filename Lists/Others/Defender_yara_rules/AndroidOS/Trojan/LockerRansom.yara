rule Trojan_AndroidOS_LockerRansom_A_2147753692_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LockerRansom.A"
        threat_id = "2147753692"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LockerRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/mycompany/myapp/MyService" ascii //weight: 1
        $x_1_2 = "Lcom/mycompany/myapp/BootReceiver" ascii //weight: 1
        $x_1_3 = "Landroid/view/WindowManager$LayoutParams" ascii //weight: 1
        $x_1_4 = "com.adrt.LOGCAT_ENTRIES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_LockerRansom_B_2147753830_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LockerRansom.B"
        threat_id = "2147753830"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LockerRansom"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "Lcom/bendel_software/anlocker/LockerService" ascii //weight: 4
        $x_1_2 = "Lcom/bendel_software/anlocker/ReceiverBootCompleted" ascii //weight: 1
        $x_1_3 = "com.adrt.LOGCAT_ENTRIES" ascii //weight: 1
        $x_1_4 = "setComponentEnabledSetting" ascii //weight: 1
        $x_1_5 = "Landroid/view/WindowManager$LayoutParams" ascii //weight: 1
        $x_1_6 = "layout_inflater" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_AndroidOS_LockerRansom_A_2147782189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LockerRansom.A!MTB"
        threat_id = "2147782189"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LockerRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.termuxhackers.id" ascii //weight: 1
        $x_1_2 = "logcat -v threadtime" ascii //weight: 1
        $x_1_3 = "com.adrt.LOGCAT_ENTRIES" ascii //weight: 1
        $x_1_4 = "Ladrt/ADRTSender" ascii //weight: 1
        $x_1_5 = "!$Devastating!7x!" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_LockerRansom_B_2147814713_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/LockerRansom.B!MTB"
        threat_id = "2147814713"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "LockerRansom"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Lcom/termuxhackers/ie/MyService" ascii //weight: 1
        $x_1_2 = "Lcom/termuxhackers/ie/BootReceiver" ascii //weight: 1
        $x_1_3 = "logcat -v threadtime" ascii //weight: 1
        $x_1_4 = "com.adrt.LOGCAT_ENTRIES" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

