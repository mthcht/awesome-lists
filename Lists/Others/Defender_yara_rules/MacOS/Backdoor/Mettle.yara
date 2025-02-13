rule Backdoor_MacOS_Mettle_2147741153_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Mettle"
        threat_id = "2147741153"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Mettle"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/mettle/mettle/src/mettle.c" ascii //weight: 1
        $x_1_2 = "/mettle/mettle/src/c2_http.c" ascii //weight: 1
        $x_1_3 = "/mettle/mettle/src/bufferev.c" ascii //weight: 1
        $x_1_4 = "/mettle/mettle/src/channel.c" ascii //weight: 1
        $x_1_5 = "/mettle/mettle/src/coreapi.c" ascii //weight: 1
        $x_1_6 = "/mettle/mettle/src/process.c" ascii //weight: 1
        $x_1_7 = "/mettle/mettle/src/service.c" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

rule Backdoor_MacOS_Mettle_A_2147750371_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:MacOS/Mettle.A!MTB"
        threat_id = "2147750371"
        type = "Backdoor"
        platform = "MacOS: "
        family = "Mettle"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_MACHOHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/mettle/mettle/src/process.c" ascii //weight: 1
        $x_1_2 = "/mettle/mettle/extensions/sniffer/sniffer.c" ascii //weight: 1
        $x_1_3 = "/mettle/mettle/src/tlv.c" ascii //weight: 1
        $x_1_4 = "_extension_log_to_mettle" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

