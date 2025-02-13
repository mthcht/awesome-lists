rule TrojanSpy_AndroidOS_SpyBnk_A_2147812784_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:AndroidOS/SpyBnk.A!MTB"
        threat_id = "2147812784"
        type = "TrojanSpy"
        platform = "AndroidOS: Android operating system"
        family = "SpyBnk"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "com.sibche.aspardproject.app" ascii //weight: 1
        $x_1_2 = "SPIDER_W9898" ascii //weight: 1
        $x_1_3 = "com/asanpardakht/jockerblock" ascii //weight: 1
        $x_1_4 = "nexhack" ascii //weight: 1
        $x_1_5 = "Hacked numbar hhelp charyty" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

