rule Trojan_Win64_SilverFox_AHB_2147959959_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilverFox.AHB!MTB"
        threat_id = "2147959959"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilverFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {49 4e 43 52 45 41 53 49 4e 47 20 52 45 56 45 41 4c 20 53 54 4f 4f 44 20 56 41 4c 49 44 41 54 49 4f 4e 20 46 41 56 4f 55 52 49 54 45 00 00 00 00}  //weight: 30, accuracy: High
        $x_20_2 = "cmd /v /c Set JmwA=cmd & !JmwA! < Passive.eml" ascii //weight: 20
        $x_10_3 = {26 8a 01 2c ?? 80 39 ?? 0f b6 d0 0f b6 01 0f 4c d0 44 0f be c2 41 8d 40 bf}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SilverFox_AKP_2147967006_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilverFox.AKP!MTB"
        threat_id = "2147967006"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilverFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {48 b8 70 d0 91 b7 ef 3f 0e 80 48 89 44 24 78 48 b8 fc 5e f3 a2 07 ee 15 3e}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SilverFox_ASF_2147969403_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilverFox.ASF!MTB"
        threat_id = "2147969403"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilverFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {48 8d 85 40 01 00 00 ba 08 02 00 00 4c 8d 0d ?? 22 00 00 48 89 44 24 20 4c 8d 05 ?? 23 00 00 48 8d 8d}  //weight: 3, accuracy: Low
        $x_2_2 = {48 8d 44 24 30 ba 08 02 00 00 4c 8d 8d 40 01 00 00 48 89 44 24 20 4c 8d 05 ?? 23 00 00 48 8d}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SilverFox_AFS_2147970437_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilverFox.AFS!MTB"
        threat_id = "2147970437"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilverFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {41 58 5a 59 41 5b 41 ff d3 0f b6 c0 8b 4d e8 31 c1 0f b6 c9 88 4d d7 48 8b 45 f8 48 8b 4d 18 48 01 c1 48 89 4d e8 0f b6 09 0f b6 45 d7 31 c1 48 8b 45 e8 88 08 48 8b 45 10 48 8b 4d 10 8b 09 c1 e1 03 48 8b 55 10 8b 12 c1 ea 1d 09 d1 8b 55 e4 31 d1 89 08}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_SilverFox_SX_2147970589_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/SilverFox.SX!MTB"
        threat_id = "2147970589"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "SilverFox"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "70"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {4c 89 7c 24 50 48 8d 15 ?? ?? ?? ?? 4c 89 7c 24 48 41 b9 ff 01 0f 00 4c 89 7c 24 40 48 8b cb 48 89 44 24 38 c7 44 24 30 01 00 00 00 c7 44 24 28 02 00 00 00 c7 44 24 20 10 00 00 00 ff 15 ?? ?? ?? ?? 48 8b f8 41 8b ef 48 85 c0 ?? ?? ?? ?? ?? ?? 4c 8d 44 24 70 4c 89 64 24 70 ba 01 00 00 00 48 8b c8 ff 15}  //weight: 30, accuracy: Low
        $x_10_2 = {05 00 00 4c 8d 05 ?? ?? ?? ?? 48 8b c8 48 8b d3 48 8d 44 24 48 48 89 44 24 20 ff 15 ?? ?? ?? ?? 45 33 c9 48 c7 44 24 28 00 00 00 00 4c 8b c3 c7 44 24 20 00 00 00 00 33 d2 33 c9 ff 15}  //weight: 10, accuracy: Low
        $x_30_3 = "Tiprundll" ascii //weight: 30
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

