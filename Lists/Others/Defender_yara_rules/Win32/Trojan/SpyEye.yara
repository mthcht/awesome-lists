rule Trojan_Win32_SpyEye_GMZ_2147893506_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyEye.GMZ!MTB"
        threat_id = "2147893506"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyEye"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8a 07 4e 03 ce 88 02 f7 d0 4e 03 c1 4b f7 d6 42 f7 d8 41 47 8b cf 41 0b db}  //weight: 10, accuracy: High
        $x_1_2 = ".cylednh" ascii //weight: 1
        $x_1_3 = ".hmlmrei" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

