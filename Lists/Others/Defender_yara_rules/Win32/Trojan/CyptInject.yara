rule Trojan_Win32_CyptInject_YBQ_2147922426_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CyptInject.YBQ!MTB"
        threat_id = "2147922426"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CyptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {8b 95 44 f3 ff ff 83 c2 01 89 95 44 f3 ff ff 8b 85 44 f3 ff ff 3b 85 f8 ed ff ff 73 ?? 53 81 cb fb 7a 01 00 81 f3}  //weight: 2, accuracy: Low
        $x_1_2 = {81 c8 2a 38 01 00 58 0f b6 8d 97 f9 ff ff 8b 95 44 f3 ff ff 0f be 02 2b c1 8b 8d 44 f3 ff ff 88 01}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_CyptInject_YBR_2147922427_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CyptInject.YBR!MTB"
        threat_id = "2147922427"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CyptInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {0f be 0c 10 8b 95 6c fd ff ff 03 95 ?? ?? ?? ?? 0f b6 02 33 c1 8b 8d ?? ?? ?? ?? 03 8d f4 f8 ff ff 88 01}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

