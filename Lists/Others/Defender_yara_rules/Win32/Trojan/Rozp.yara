rule Trojan_Win32_Rozp_A_2147658256_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rozp.A"
        threat_id = "2147658256"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rozp"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "spdg.dll" ascii //weight: 1
        $x_1_2 = {8b f9 03 7d 08 8a 07 04 ?? 88 07 41 3b 4d 0c 73 02 eb ed c9}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

