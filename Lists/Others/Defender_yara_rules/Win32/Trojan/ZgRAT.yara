rule Trojan_Win32_ZgRAT_A_2147902541_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZgRAT.A!MTB"
        threat_id = "2147902541"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {66 ad 66 83 f0 ?? 66 ab 66 83 f8}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_ZgRAT_NG_2147915528_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ZgRAT.NG!MTB"
        threat_id = "2147915528"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ZgRAT"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {69 8d 94 fd ff ff ?? ?? ?? ?? 2b c1 33 d0 0f af 95 94 fd ff ff 89 95 14 e1 ff ff 8b 95 14 e1 ff ff 89 95 10 e1 ff ff 83 bd 10 e1 ff ff 00 0f 86 f5 04 00 00 52}  //weight: 3, accuracy: Low
        $x_1_2 = "InternetOpenUrlW" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

