rule Trojan_Win32_AmsiBypass_LRA_2147973366_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/AmsiBypass.LRA!MTB"
        threat_id = "2147973366"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "AmsiBypass"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_20_1 = {8b 55 f8 66 8b 02 66 89 45 ea 83 45 f8 02 66 83 7d ea 00 75 ?? 8b 4d f8 2b 4d cc d1 f9 89 4d c8 83 7d c8 40 76 05}  //weight: 20, accuracy: Low
        $x_10_2 = {8b 45 ec 66 8b 48 02 66 89 4d e6 83 45 ec 02 66 83 7d e6 00 75 ?? 8b 7d ec 8b 75 c0 8b 55 bc 8b ca c1 e9 02 f3 a5 8b ca 83 e1 03 f3 a4 8d 45 d4}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

