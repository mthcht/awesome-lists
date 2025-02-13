rule Trojan_Win32_ZharkBot_WFB_2147919286_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZharkBot.WFB!MTB"
        threat_id = "2147919286"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZharkBot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f7 e9 03 d1 c1 fa 05 8b c2 c1 e8 1f 03 c2 8a c8 c0 e1 03 2a c8 c0 e1 03 8a 45 dc 2a c1 04 39 8b 4d dc 30 84 0d b1 f6 ff ff 41 89 4d dc 83 f9 33}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

