rule Trojan_Win64_CrypInject_AFX_2147817949_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CrypInject.AFX!MTB"
        threat_id = "2147817949"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CrypInject"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 44 24 44 3b 84 24 ?? ?? ?? ?? 7d 2b 8b 84 24 ?? ?? ?? ?? 48 8b 4c 24 ?? 33 01 89 01 48 8b 44 24 ?? 48 83 c0 04 48 89 44 24 78 8b 44 24 44 83 c0 01 89 44 24 44 eb c8}  //weight: 10, accuracy: Low
        $x_1_2 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

