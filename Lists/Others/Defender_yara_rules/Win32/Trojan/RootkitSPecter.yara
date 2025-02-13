rule Trojan_Win32_RootkitSPecter_CB_2147806310_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RootkitSPecter.CB!MTB"
        threat_id = "2147806310"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RootkitSPecter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {8b 44 24 04 8d 0c 02 8a 04 02 84 c0 74 06 2c 59 34 0c 88 01 42 3b 54 24 08 7c e5}  //weight: 1, accuracy: High
        $x_1_2 = {8b 44 24 04 03 c1 8a 10 80 ea 63 80 f2 61 41 3b 4c 24 08 88 10 7c e9}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

