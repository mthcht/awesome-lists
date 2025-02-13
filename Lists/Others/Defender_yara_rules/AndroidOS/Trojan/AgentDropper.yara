rule Trojan_AndroidOS_AgentDropper_AZB_2147798016_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/AgentDropper.AZB"
        threat_id = "2147798016"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "AgentDropper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dEWYdWYcjplAwQTdgbzopl_961843" ascii //weight: 1
        $x_1_2 = "muting_enabled" ascii //weight: 1
        $x_1_3 = "collectionsRoot" ascii //weight: 1
        $x_1_4 = "reactionPickerHint" ascii //weight: 1
        $x_1_5 = "OnlyIfRunning" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

