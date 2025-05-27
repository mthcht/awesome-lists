rule Trojan_AndroidOS_Necro_A_2147759371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Necro.A!MTB"
        threat_id = "2147759371"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Necro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "useStartNotify" ascii //weight: 1
        $x_1_2 = "useFullInject" ascii //weight: 1
        $x_1_3 = "Lsdk/nicro/web" ascii //weight: 1
        $x_1_4 = "webadlist" ascii //weight: 1
        $x_1_5 = "executedSearchUrls" ascii //weight: 1
        $x_1_6 = "Debug.webExec" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_AndroidOS_Necro_B_2147942313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/Necro.B!MTB"
        threat_id = "2147942313"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "Necro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 20 56 00 53 00 0a 06 12 f7 32 76 7b 00 71 20 b8 00 65 00 0c 06 21 27 21 68 b0 87 23 78 74 00 21 29 71 59 90 00 12 18 21 22 21 69 71 59 90 00 16 28 74 01 b6 00 12 00 0c 02}  //weight: 1, accuracy: High
        $x_1_2 = {0c 01 6e 10 65 00 00 00 0c 00 6e 20 85 00 20 00 0c 00 12 32 46 00 00 02 62 02 2b 00 6e 20 82 00 20 00 0c 00 21 13 21 04 12 05 12 06 12 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

