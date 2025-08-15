rule Trojan_Win32_Lycaon_Z_2147949417_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.Z!MTB"
        threat_id = "2147949417"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {95 de f7 ff ff b8 65 00 00 00 66 89 85 e0 f7 ff ff b9 6c 00 00 00 66 89 8d e2 f7 ff ff ba 33 00 00 00 66 89 95 e4 f7 ff ff b8 32 00 00 00 66 89 85 e6 f7 ff ff b9 2e 00 00 00 66 89 8d e8 f7 ff}  //weight: 1, accuracy: High
        $x_1_2 = {95 9c fb ff ff 83 c2 02 89 95 9c fb ff ff 66 8b 85 86 fa ff ff 66 89 85 60 ff ff ff 8b 8d 98 fb ff ff 66 8b 11 66 89 95 84 fa ff ff 8b 85 98 fb ff ff 83 c0 02 89 85 98 fb ff ff 66 8b 8d 84 fa}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_ZZ_2147949418_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.ZZ!MTB"
        threat_id = "2147949418"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {33 c0 50 50 6a 05 8d 4d f4 51 6a 01 8d 8d 44 e5 ff ff 51 50 ff b5 20 e5 ff ff 43 ff 85 40 e5 ff ff ff 15 78 a0 48 00 8b f0 85 f6 0f 84 3d 04 00 00 6a 00 8d 85 2c e5 ff ff 50 56 8d 45 f4 50 8b 85 24 e5 ff ff 8b 00 ff 34 07}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_Y_2147949419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.Y!MTB"
        threat_id = "2147949419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {2d 2b c8 8b 95 c4 fd ff ff 81 c2 8f 79 1a 1b 33 d1 0f af 95 c8 fd ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Lycaon_C_2147949420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lycaon.C!MTB"
        threat_id = "2147949420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lycaon"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b4 21 80 f8 3c c0 10 00 8b 8d ac fe ff ff 8b 95 08 fa ff ff 8b 85 64 ff ff ff 03 04 8a 89 85 a8 fe ff ff 8b 8d ac fe ff ff 8b 95 04 fa ff ff 0f b7 04 4a 8b 8d 00 fa ff ff 8b 95 64 ff ff ff}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

