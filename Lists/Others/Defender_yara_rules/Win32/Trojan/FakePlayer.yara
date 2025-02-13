rule Trojan_Win32_FakePlayer_A_2147641864_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakePlayer.A"
        threat_id = "2147641864"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePlayer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 85 c2 00 00 00 80 7d ?? 47 0f 85 ?? ?? 00 00 80 7d ?? 49 0f 85 ?? ?? 00 00 80 7d ?? 46 0f 85 ?? ?? 00 00 80 7d ?? 38 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_2_2 = {75 09 80 81 ?? ?? ?? 00 fd eb 33 8b c1 6a 03 99 5f f7 ff 85 d2 75 08 fe 89 ?? ?? ?? 00 eb 1f}  //weight: 2, accuracy: Low
        $x_1_3 = "\\MyIEData\\main.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_FakePlayer_B_2147642528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/FakePlayer.B"
        threat_id = "2147642528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "FakePlayer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {0f 85 c2 00 00 00 80 7d ?? 47 0f 85 ?? ?? 00 00 80 7d ?? 49 0f 85 ?? ?? 00 00 80 7d ?? 46 0f 85 ?? ?? 00 00 80 7d ?? 38 0f 85 ?? ?? 00 00}  //weight: 1, accuracy: Low
        $x_2_2 = {75 09 80 81 ?? ?? ?? 00 fd eb 33 8b ?? 6a 03 99 ?? f7 ?? 85 ?? 75 08 fe 89 ?? ?? ?? 00 eb 1f}  //weight: 2, accuracy: Low
        $x_1_3 = "vnetservices.l0086.com.cn" ascii //weight: 1
        $x_1_4 = "\\NethomeInfo\\MyIEData\\main.ini" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

