rule Trojan_Win32_Syammi_CRDV_2147850812_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Syammi.CRDV!MTB"
        threat_id = "2147850812"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Syammi"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8d 4c 02 18 8b 95 6c ff ff ff 03 95 98 fe ff ff 33 ca 88 4d fe 0f b7 85 5c ff ff ff 8b 4d d0 8d 54 01 22 2b 15 ?? ?? ?? ?? 83 c2 21 88 95 47 ff ff ff 0f b7 85 7c ff ff ff 83 e8 34 89 85 d8 fe ff ff e9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

