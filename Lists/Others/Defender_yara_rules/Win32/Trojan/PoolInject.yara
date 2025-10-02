rule Trojan_Win32_PoolInject_MR_2147948294_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PoolInject.MR!MTB"
        threat_id = "2147948294"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stop reversing the binary" ascii //weight: 1
        $x_1_2 = "Reconsider your life choices" ascii //weight: 1
        $x_1_3 = "And go touch some grass" ascii //weight: 1
        $x_1_4 = "Fail to schedule the chore!" ascii //weight: 1
        $x_1_5 = "future already retrieved" ascii //weight: 1
        $x_1_6 = "promise already satisfied" ascii //weight: 1
        $x_2_7 = {41 ba 40 00 00 00 41 8b c8 48 8b d0 83 e1 3f 44 2b d1 41 0f b6 ca 48 d3 ca 49 33 d0}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PoolInject_SXD_2147953852_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PoolInject.SXD!MTB"
        threat_id = "2147953852"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PoolInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8b 44 24 30 48 c7 40 10 00 ?? ?? ?? 48 8b 44 24 30 c7 40 18 ?? ?? ?? ?? 4c 8d 0d ?? ?? ?? ?? 48 8b 44 24 30 44 8b 40 08 33 d2 33 c9 ff 15 ?? ?? ?? ?? 48 8b 4c 24 30}  //weight: 3, accuracy: Low
        $x_2_2 = {8b 44 24 2c 3b 84 24 88 00 00 00 7d ?? 48 8b 44 24 48 48 63 4c 24 2c 0f b6 04 08 03 44 24 30 89 44 24 30 8b 44 24 2c 83 c0 ?? 89 44 24 2c eb d0}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

