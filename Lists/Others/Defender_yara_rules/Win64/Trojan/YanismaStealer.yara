rule Trojan_Win64_YanismaStealer_DA_2147899866_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/YanismaStealer.DA!MTB"
        threat_id = "2147899866"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "YanismaStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "hackirby/skuld/" ascii //weight: 1
        $x_1_2 = "walletsinjection" ascii //weight: 1
        $x_1_3 = "uacbypass" ascii //weight: 1
        $x_1_4 = "ChromiumSteal" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

