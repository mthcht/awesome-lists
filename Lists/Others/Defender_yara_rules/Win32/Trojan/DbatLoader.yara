rule Trojan_Win32_DbatLoader_RP_2147911049_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DbatLoader.RP!MTB"
        threat_id = "2147911049"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DbatLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {4e 63 32 35 ?? ?? ?? ?? ?? 5e 5e 4e 63 32 50 32 3e 5b 60 5d 23 32 50 32 3e 5b 60 5d 24 32 50 32 5a 66 66 62 65 2c 21 21}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

