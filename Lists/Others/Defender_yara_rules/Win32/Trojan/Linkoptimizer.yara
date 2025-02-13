rule Trojan_Win32_Linkoptimizer_17621_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Linkoptimizer"
        threat_id = "17621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Linkoptimizer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 00 31 2e 64 6c 6c 00 00 00 5c 00 00 00 43 3a 5c 00 63 3a 5c 77 69 6e 64 6f 77 73 00 00 77 69 6e 64 69 72 00 00 53 59 53 54 45 4d 52 4f 4f 54 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 2e 64 6c 6c 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73}  //weight: 2, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Linkoptimizer_17621_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Linkoptimizer"
        threat_id = "17621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Linkoptimizer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 00 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 2e 64 6c 6c 00 00 5c 4c 69 6e 6b 4f 70 74 69 6d 69 7a 65 72 00 00 43 3a 5c 50 72 6f 67 72 61 6d 20 46 69 6c 65 73 00 00 00 00 50 72 6f 67 72 61 6d 46 69 6c 65 73 00}  //weight: 2, accuracy: High
        $x_1_2 = {6e 75 6c 00 00 4f 70 65 6e 00 00 00 00 2f 63 20 64 65 6c 20 00 43 4f 4d 53 50 45 43}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Linkoptimizer_17621_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Linkoptimizer"
        threat_id = "17621"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Linkoptimizer"
        severity = "High"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "uid=%08x%08x%08x&di=%08x&pin=%05d&life=%d&lt=%d&v0=1&l=%d&d=%d&u=%d&act=%d&ic=%d" ascii //weight: 2
        $x_2_2 = "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\LinkOptimizer" ascii //weight: 2
        $x_2_3 = "&act=gc&pin=%5d&d=%s" ascii //weight: 2
        $x_2_4 = "http://www.flashkin.net" ascii //weight: 2
        $x_2_5 = "lautoclick" wide //weight: 2
        $x_2_6 = "_STEALTH_LINK_" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

