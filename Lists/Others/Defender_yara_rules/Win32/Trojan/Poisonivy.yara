rule Trojan_Win32_Poisonivy_MBXR_2147918937_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Poisonivy.MBXR!MTB"
        threat_id = "2147918937"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Poisonivy"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {b0 25 40 00 78 12 40 00 00 f0 30 00 00 ff ff ff 08 00 00 00 01 00 00 00 00 00 00 00 e9 00 00 00 0c 11 40 00 0c 11 40 00 d0 10 40 00 78 00 00 00 80}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

