rule Trojan_Win32_Nexrops_A_2147705527_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nexrops.A"
        threat_id = "2147705527"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nexrops"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {43 3a 5c 57 69 6e 64 6f 77 73 5c 53 79 73 74 65 6d 33 32 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {5c 57 69 6e 64 6f 77 73 5c 43 75 72 72 65 6e 74 56 65 72 73 69 6f 6e 5c 52 75 6e 5c [0-16] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "qweasdzxc123" ascii //weight: 1
        $x_1_4 = "ftp://xiaodai.hk.wuxb.com" ascii //weight: 1
        $x_1_5 = {44 3a 5c 00 45 3a 5c 00 46 3a 5c}  //weight: 1, accuracy: High
        $x_1_6 = "27bb20fdd3e145e4bee3db39ddd6e64c" ascii //weight: 1
        $x_1_7 = "d09f2340818511d396f6aaf844c7e325" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (6 of ($x*))
}

