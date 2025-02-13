rule Trojan_Win32_Omssun_2147609281_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Omssun"
        threat_id = "2147609281"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Omssun"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {85 c0 74 34 8d 44 37 f3 8b f7 3b f8 73 2a b2 84 b1 eb 80 3e e8 75 1c 80 7e 05 85 75 16 80 7e 06 c0 75 10 80 7e 07 0f 75 0a 38 56 08 75 05 38 4e 0d 74 1d 46 3b f0 72 da}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

