rule Trojan_Win32_Mebroot_GMF_2147888460_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Mebroot.GMF!MTB"
        threat_id = "2147888460"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Mebroot"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {8b 00 8b 70 08 8b 46 3c 8b 44 30 78 03 c6 8b 78 20 03 fe 83 65 f4 00 c7 45 ?? 47 65 74 50 c7 45 ?? 72 6f 63 41 c7 45 ?? 64 64 72 65 c7 45 ?? 73 73 00 00 8b 4d f4 8b 14 8f 03 d6 ff 45 f4 8d 4d d8 89 4d ec 0f b6 0a 83 e9 47}  //weight: 10, accuracy: Low
        $x_1_2 = "%sibm%05d.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

