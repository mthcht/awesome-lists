rule Trojan_Win32_KryptInject_DSK_2147742601_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KryptInject.DSK!MTB"
        threat_id = "2147742601"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {0f b6 04 18 30 83 ?? ?? ?? ?? 8b 45 fc 8d b0 ?? ?? ?? ?? b8 25 49 92 24 03 f3 f7 e6 b8 ?? ?? ?? ?? 2b f2 d1 ee 03 f2 c1 ee 04 8d 0c f5 00 00 00 00 2b ce c1 e1 02 2b c1 0f b6 04 18}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KryptInject_PDSK_2147742669_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KryptInject.PDSK!MTB"
        threat_id = "2147742669"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KryptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {8f 45 f8 31 4d f8 8b 55 f8 8b ca b8 89 dc 00 00 03 c1 2d 89 dc 00 00 89 45 fc}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

