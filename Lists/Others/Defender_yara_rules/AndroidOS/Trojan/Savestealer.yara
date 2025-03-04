rule Trojan_AndroidOS_Savestealer_B_2147828244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Savestealer.B!MTB"
        threat_id = "2147828244"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Savestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {65 74 65 72 6e 69 74 79 70 72 2e [0-3] 2f 61 70 69 2f 61 63 63 6f 75 6e 74 73}  //weight: 1, accuracy: Low
        $x_1_2 = "Lcom/eternity/" ascii //weight: 1
        $x_1_3 = {73 61 76 65 64 61 74 00}  //weight: 1, accuracy: High
        $x_1_4 = {77 65 62 68 6f 6f 6b 75 72 6c 00}  //weight: 1, accuracy: High
        $x_1_5 = "/com.rtsoft.growtopia/files/save.dat" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Savestealer_C_2147829345_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Savestealer.C!MTB"
        threat_id = "2147829345"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Savestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/surferstubs/autostart;" ascii //weight: 1
        $x_1_2 = "/surferstubs/Trace;" ascii //weight: 1
        $x_1_3 = "/GrowLauncherTrace;" ascii //weight: 1
        $x_1_4 = "startWatching" ascii //weight: 1
        $x_1_5 = "jni_get_mtu" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Savestealer_D_2147829666_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Savestealer.D!MTB"
        threat_id = "2147829666"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Savestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vpnservice.VhostsService" ascii //weight: 1
        $x_1_2 = "avggrip" ascii //weight: 1
        $x_1_3 = "webhookurl" ascii //weight: 1
        $x_1_4 = "allmacs" ascii //weight: 1
        $x_1_5 = "startWatching" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Trojan_AndroidOS_Savestealer_E_2147830702_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Savestealer.E!MTB"
        threat_id = "2147830702"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Savestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "_Check_Internet_Connection" ascii //weight: 1
        $x_1_2 = "_uploadToServer_request_listener" ascii //weight: 1
        $x_1_3 = "initializeLogic" ascii //weight: 1
        $x_1_4 = "StringFogImpl" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Savestealer_F_2147842141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Savestealer.F!MTB"
        threat_id = "2147842141"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Savestealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com/robbob/gaming" ascii //weight: 1
        $x_1_2 = "allmacs" ascii //weight: 1
        $x_1_3 = "webhookurl" ascii //weight: 1
        $x_1_4 = "startWatching" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Savestealer_A_2147897295_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Savestealer.A"
        threat_id = "2147897295"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Savestealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "WUlqdld4bFhrQWpabkw0czRDVmVGVVFiT1NMaG91OE9NUU53ZXk5T01PSUl6TERXZGQ" ascii //weight: 2
        $x_2_2 = "MpLBFU7IMbFeTuvF" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Savestealer_HT_2147919244_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Savestealer.HT"
        threat_id = "2147919244"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Savestealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aHR0cHM6Ly9ldGVybml0eXByLm5ldC9hcGkvYWNjb3VudHM" ascii //weight: 1
        $x_1_2 = "UHMqcRVlYSIbYnghXVtMZ2hfF04MXSJhSW16KUNydiVVFQBubB0ASVBBJWMCJGwnQA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

