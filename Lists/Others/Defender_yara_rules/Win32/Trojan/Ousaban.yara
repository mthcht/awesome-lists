rule Trojan_Win32_Ousaban_2147789535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ousaban!MTB"
        threat_id = "2147789535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ousaban"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {5e 37 24 44 67 5a e9 42 8d 94 ab 7f 58 c7 cd 67 0f d4 a5 a6 40 a4 59 9a 06 e2 b0 1b 99 47 77 a4 74 96 a3 5d 4e 17 a8 44 ca f6 c2 79 a9 ac cc}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ousaban_C_2147828851_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ousaban.C"
        threat_id = "2147828851"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ousaban"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {f1 d5 00 fa 4c 62 cc f4 0f 0b}  //weight: 1, accuracy: High
        $x_10_2 = "#ON-LINE#" ascii //weight: 10
        $x_10_3 = "#strPingOk#" ascii //weight: 10
        $x_10_4 = "#xyScree#" ascii //weight: 10
        $x_10_5 = "#strIniScree#" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Ousaban_GTM_2147928990_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Ousaban.GTM!MTB"
        threat_id = "2147928990"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Ousaban"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {47 32 4d 00 00 00 00 02 00 00 00 8b ?? ?? ?? ?? 81 c4 ?? ?? ?? ?? 53 56 57 33 d2 89 95 ?? ?? ?? ?? 89 95 ?? ?? ?? ?? 89 45 ?? 8b 45}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

