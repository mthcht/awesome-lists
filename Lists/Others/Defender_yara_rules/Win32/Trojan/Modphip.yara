rule Trojan_Win32_Modphip_A_2147627603_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Modphip.A"
        threat_id = "2147627603"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Modphip"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {76 69 73 75 61 6c 73 74 75 64 69 6f 73 72 63 33 6b 33 00}  //weight: 1, accuracy: High
        $x_1_2 = {69 64 2e 70 68 70 3f 72 61 6e 64 6f 6d 3d 00}  //weight: 1, accuracy: High
        $x_1_3 = {73 68 75 74 64 6f 77 6e 20 2d 72 20 2d 74 20 30 00}  //weight: 1, accuracy: High
        $x_1_4 = "update.php?os=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

