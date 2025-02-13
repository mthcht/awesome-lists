rule Trojan_Win32_Locky_GK_2147891921_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Locky.GK!MTB"
        threat_id = "2147891921"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Locky"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {7c 44 8b 6c 24 14 03 6c 24 04 8b 74 24 1c 03 34 24 8a 6d 00 8a 0e 31 f6 31 f6 31 f6 30 cd 30 cd 30 cd 88 6d 00 8b 1c 24 43 89 1c 24 8b 1c 24 8b 7c 24 20 4f 39 fb 7e 07}  //weight: 5, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

