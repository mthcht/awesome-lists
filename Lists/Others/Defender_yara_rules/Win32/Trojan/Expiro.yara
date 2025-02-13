rule Trojan_Win32_Expiro_Z_2147923634_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Expiro.Z!MTB"
        threat_id = "2147923634"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Expiro"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2e 72 65 6c 6f 63 00 00 00 [0-21] 00 00 00 00 00 00 00 00 00 00 00 00 40 00 00 e2}  //weight: 1, accuracy: Low
        $x_1_2 = {8d 4c 24 04 83 e4 f0 31 c0 ff 71 fc 55 89 e5 57 56 8d 55 a4 53 89 d7 51 b9 11 00 00 00 83 ec 78}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

