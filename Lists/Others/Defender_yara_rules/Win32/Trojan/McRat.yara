rule Trojan_Win32_McRat_2147816564_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/McRat!MTB"
        threat_id = "2147816564"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "McRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {2b ce bf 07 07 00 00 8a 14 01 80 f2 [0-1] 88 10 40 4f 75}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

