rule Trojan_Win32_Allaple_ALL_2147927741_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Allaple.ALL!MTB"
        threat_id = "2147927741"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Allaple"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 3e 02 00 00 b8 ?? ?? ?? ?? 50 ba ce 47 6c a0 e8 ?? ?? ?? ?? eb 09 31 10 83 c0 04 49}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

