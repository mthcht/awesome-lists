rule Trojan_Win64_Quasar_NSU_2147846189_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Quasar.NSU!MTB"
        threat_id = "2147846189"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e8 bb bd 00 00 48 8b 4c 24 ?? 48 89 ca 48 c1 e1 ?? 48 bb 00 00 00 00 c0 00 00 00 48 09 d9 48 89 08 48 8b 0d 28 f3 22 00 48 89 48 ?? 48 89 05 1d f3 22 00 48 8d 42 ?? 48 85 c0 7d b6}  //weight: 5, accuracy: Low
        $x_1_2 = "onuxH" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Quasar_AMA_2147922146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Quasar.AMA!MTB"
        threat_id = "2147922146"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "E:\\hacktools" ascii //weight: 2
        $x_1_2 = "stageless\\test\\x64\\Release\\test.pdb" ascii //weight: 1
        $x_1_3 = "Black.Myth.Wukong.Trainer.V1.4.2-XiaoXing" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Quasar_AQU_2147922155_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Quasar.AQU!MTB"
        threat_id = "2147922155"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {41 ff c0 8b c8 41 8a 04 06 32 02 48 ff c2 88 04 0e 45 3b c1}  //weight: 5, accuracy: High
        $x_3_2 = {48 8b cf ff 15 ?? ?? ?? ?? 48 8d 15 3c 68 01 00 48 8b cf 48 89 05 72 ac 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 3d 68 01 00 48 8b cf 48 89 05 3b ac 01 00 ff 15 ?? ?? ?? ?? 48 8d 15 3e 68 01 00 48 8b cf}  //weight: 3, accuracy: Low
        $x_2_3 = "http://139.180.202.227:8080" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Quasar_AUQ_2147943628_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Quasar.AUQ!MTB"
        threat_id = "2147943628"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 89 4d 10 48 89 55 18 c7 45 fc 00 00 00 00 c7 45 f8 00 00 00 00 eb ?? 8b 4d f8 48 63 c1 48 69 c0 ?? ?? ?? ?? 48 c1 e8 20 48 89 c2 89 c8 c1 f8 1f 29 c2 89 d0 01 c0 01 d0 29 c1 89 ca 89 d0 0f af 45 f8 01 45 fc 83 45 f8 01}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8b 85 e8 ?? ?? ?? 48 8d 15 b0 82 00 00 48 89 c1 48 8b 05 31 d5 00 00 ff d0 48 89 85 e0 ?? ?? ?? 48 8b 85 e8 ?? ?? ?? 48 8d 15 9e 82 00 00 48 89 c1 48 8b 05 10 d5 00 00 ff d0 48 89 85 d8 ?? ?? ?? 48 8b 85 e8 ?? ?? ?? 48 8d 15}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_Quasar_AQS_2147953088_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Quasar.AQS!MTB"
        threat_id = "2147953088"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Quasar"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be 11 48 83 c1 01 01 c2 89 d0 c1 e0 07 01 d0 89 c2 c1 ea 06 31 d0 4c 39 c1}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

