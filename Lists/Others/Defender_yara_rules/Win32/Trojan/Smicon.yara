rule Trojan_Win32_Smicon_2147638472_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Smicon"
        threat_id = "2147638472"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Smicon"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {53 6f 66 74 77 61 72 65 5c 69 63 6f 6e 20 67 75 69 64 65 00}  //weight: 1, accuracy: High
        $x_1_2 = "/smarticon/install.php?mac=%s&partner=%s" ascii //weight: 1
        $x_1_3 = "/count/install.php?mac=%s&partner=%s" ascii //weight: 1
        $x_1_4 = {2f 6e 65 77 75 70 64 61 74 65 72 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

