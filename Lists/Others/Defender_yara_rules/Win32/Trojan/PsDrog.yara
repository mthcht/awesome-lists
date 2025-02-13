rule Trojan_Win32_PsDrog_A_2147843116_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDrog.A!MTB"
        threat_id = "2147843116"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDrog"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {a1 d8 7b 54 00 25 ?? ?? ?? ?? 8a 80 08 5f 54 00 8b 15 d8 7b 54 00 30 82 44 36 46 00 ff 05 d8 7b 54 00 81 3d d8 7b 54 00 c2 28 0e 00 75}  //weight: 2, accuracy: Low
        $x_2_2 = {b8 23 00 00 00 e8 e6 11 fa ff ba bc 1a 46 00 8a 14 02 8d 45 ec e8 ?? ?? ?? ?? 8b 55 ec b8 e0 7b 54 00 e8 ?? ?? ?? ?? ff 05 d8 7b 54 00 83 3d d8 7b 54 00 20 75}  //weight: 2, accuracy: Low
        $x_2_3 = "-ep bypass -windowstyle hidden -file" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

