rule Trojan_Win32_Dulkit_A_2147654263_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dulkit.A"
        threat_id = "2147654263"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dulkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5." ascii //weight: 1
        $x_1_2 = {43 3a 5c 77 69 6e 64 6f 77 73 5c 65 78 74 5f 64 72 69 76 65 72 2e 65 78 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "/stat.php?u=dima&k=Ok" ascii //weight: 1
        $x_1_4 = "/driver.php?c=" ascii //weight: 1
        $x_1_5 = "/driver.php?u=" ascii //weight: 1
        $x_1_6 = {41 70 70 45 76 65 6e 74 73 5c 53 63 68 65 6d 65 73 5c 41 70 70 73 5c 45 78 70 6c 6f 72 65 72 5c 4e 61 76 69 67 61 74 69 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Dulkit_B_2147654520_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dulkit.B"
        threat_id = "2147654520"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dulkit"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {80 7d fe 00 74 30 83 7e 04 00 0f 95 c0 84 d8 74 18 ff 76 10 68 ?? ?? ?? ?? ff 75 f4 8d 45 f4 ba 03 00 00 00}  //weight: 1, accuracy: Low
        $x_1_2 = {33 68 69 54 69 6d 65 72 00 10 da 68 69 48 54 54 50 5f 47 65 74}  //weight: 1, accuracy: High
        $x_1_3 = {ce eb e5 e3 5c 44 65 73}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

