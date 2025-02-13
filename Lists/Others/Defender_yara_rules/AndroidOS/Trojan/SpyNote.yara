rule Trojan_AndroidOS_SpyNote_B_2147795503_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyNote.B"
        threat_id = "2147795503"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "VHhrevWver" ascii //weight: 1
        $x_1_2 = "BTRervqe" ascii //weight: 1
        $x_1_3 = "Lsplash/playgo" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyNote_TA_2147808762_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyNote.TA!MTB"
        threat_id = "2147808762"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {12 03 12 45 1a 01 35 01 71 10 98 02 01 00 0a 01 2b 01 ?? ?? 00 00 12 11 01 12 01 54 07 01 21 06 98 00 05 04 d8 00 00 ff df 04 00 20 32 62 ?? ?? 49 00 01 02 95 05 08 04 b7 05 d8 08 08 ff d8 00 02 01 8e 55 50 05 01 02 01 02 28 f1 71 30 c7 02 31 06 0c 00 6e 10 b5 02 00 00 0c 00 11 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyNote_T_2147835335_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyNote.T"
        threat_id = "2147835335"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.appser.verapp" ascii //weight: 1
        $x_1_2 = "Start Accessibility" ascii //weight: 1
        $x_1_3 = "Gmail<Forget-Password<Forget-Password" ascii //weight: 1
        $x_1_4 = "Facebook<Facebook Not installed<Facebook Not installed" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyNote_K_2147837274_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyNote.K!MTB"
        threat_id = "2147837274"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {08 0a 3d 00 77 00 bc 18 00 00 0c 20 14 23 8b a1 1a 00 77 00 e7 1d 00 00 0c 1f 77 01 bb 18 1f 00 0a 1f 97 23 23 1f 14 21 59 91 1a 00 77 00 f4 1f 00 00 0c 1f 77 01 bb 18 1f 00 0a 1f 97 21 21 1f 14 22 11 9b 1a 00 77 00 e4 1e 00 00 0c 1f 77 01 bb 18 1f 00 0a 1f 97 22 22 1f 77 04 ba 18 20 00 0c 20 08 00 20 00 12 31 71 20 e8 20 10 00 0a 01 12 02 13 03 31 00 12 14 33 31 1a 00 22 01 56 03 71 10 c4 20 0a 00 0c 05 70 20 5d 1a 51 00 5b a1 d0 0b 71 10 ab 1c 0a 00 0c 01 71 10 bb 20 01 00 0a 01 38 01 03 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_SpyNote_AK_2147899665_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SpyNote.AK!MTB"
        threat_id = "2147899665"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SpyNote"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/Config/sys/apps/log/log-" ascii //weight: 1
        $x_1_2 = "ActivSend" ascii //weight: 1
        $x_1_3 = "askkeyprim" ascii //weight: 1
        $x_1_4 = "getrequierdprims" ascii //weight: 1
        $x_1_5 = "_ask_remove_" ascii //weight: 1
        $x_1_6 = "name_key" ascii //weight: 1
        $x_1_7 = "Auto_Click" ascii //weight: 1
        $x_1_8 = "screenshotresult" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

