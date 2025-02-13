rule Trojan_Win32_Bootstrapper_A_2147929171_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bootstrapper.A"
        threat_id = "2147929171"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bootstrapper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b cb c1 e1 04 03 4d d8 8d 14 18 33 ca 33 4d f8}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

