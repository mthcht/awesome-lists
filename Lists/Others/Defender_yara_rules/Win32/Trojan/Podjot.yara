rule Trojan_Win32_Podjot_A_2147643054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Podjot.A"
        threat_id = "2147643054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Podjot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {74 6f 6f 6b 6f 6f 64 6f 6f 5f 70 72 6f 6a 78 2e 64 6c 6c 00 53 74 61 72 74 75 70}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

