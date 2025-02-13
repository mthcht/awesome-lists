rule Trojan_AndroidOS_Dvmap_A_2147820332_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Dvmap.A!xp"
        threat_id = "2147820332"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Dvmap"
        severity = "Critical"
        info = "xp: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ELFHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/data/local/tmp/.localtmptest.apk" ascii //weight: 1
        $x_1_2 = "/system/xbin/busybox" ascii //weight: 1
        $x_1_3 = "/mnt/secure/asec/smdl2tmp1.asec" ascii //weight: 1
        $x_1_4 = "/system/etc/install_recovery.sh" ascii //weight: 1
        $x_1_5 = "data/local/tmp/android_iccd.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Dvmap_B_2147902891_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Dvmap.B!MTB"
        threat_id = "2147902891"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Dvmap"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "15.threadstart" ascii //weight: 1
        $x_1_2 = "Y29tLnF1YWxjbW0udGltZXNlcnZpY2Vz" ascii //weight: 1
        $x_1_3 = "Game32%d.res" ascii //weight: 1
        $x_1_4 = "root_fail" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

