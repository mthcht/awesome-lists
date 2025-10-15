rule Trojan_Win32_Vindor_AHB_2147955081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Vindor.AHB!MTB"
        threat_id = "2147955081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Vindor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "60"
        strings_accuracy = "Low"
    strings:
        $x_30_1 = {33 f6 03 df ff 15 ?? ?? ?? 00 25 ?? ?? ?? ?? 79 ?? 48 0d ?? ?? ?? ?? 40 88 04 33 46 83 fe ?? 7c ?? 8d 8c 24 d0 03 00 00}  //weight: 30, accuracy: Low
        $x_20_2 = "ADAMANDPRASHANTAREAWESOME" ascii //weight: 20
        $x_10_3 = "[!]Failed to get echo port from server" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

