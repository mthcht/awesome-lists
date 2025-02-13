rule Trojan_AndroidOS_SoumniBot_C_2147915766_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:AndroidOS/SoumniBot.C"
        threat_id = "2147915766"
        type = "Trojan"
        platform = "AndroidOS: Android operating system"
        family = "SoumniBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_DEXHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "softwareapp/BootBroadcastReceiver" ascii //weight: 2
        $x_2_2 = "d3NzOi8vd3d3Lm1ha2U2OS5pbmZvOjg3NjU=" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

