rule Trojan_MSIL_darkcloud_ZUN_2147953658_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/darkcloud.ZUN!MTB"
        threat_id = "2147953658"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "darkcloud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_6_1 = {91 11 04 1f 16 91 59 0d 2b ab 16 0a 1a 0d 2b a5 03 04 61 1f 7f 59 06 61 45 ?? 00 00 00 05 00 00 00 0f 00 00 00 13 00 00 00 1f 0b 0d 2b 87 11 05 20 22 01 00 00 91 2b f3 1f 0d 2b ef 11 04}  //weight: 6, accuracy: Low
        $x_4_2 = {28 50 00 00 0a 0b 11 04 20 03 01 00 00 91 0d 38 ?? ff ff ff 02 28 ?? 00 00 0a 0b 11 04 20 03 01 00 00 91 0d 38 ?? ff ff ff 02 28 ?? 00 00 0a 0b 11 04 20 12 01 00 00 91 1d 59}  //weight: 4, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

