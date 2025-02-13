rule Trojan_Win32_Antonia_A_2147706054_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antonia.A"
        threat_id = "2147706054"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antonia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "checkregupdates.eu" ascii //weight: 1
        $x_1_2 = "v=%d&u=%s&c=%d&f=%d&a=%d&d=%d" ascii //weight: 1
        $x_1_3 = "Software\\DefendrvPro" wide //weight: 1
        $x_1_4 = "C:\\Users\\Anton\\Documents\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Antonia_B_2147706440_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Antonia.B"
        threat_id = "2147706440"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Antonia"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "v=%d&a=%d&i=%d&f=%d&u=%s" ascii //weight: 1
        $x_1_2 = {4c 00 6f 00 63 00 61 00 6c 00 00 00 4c 00 6f 00 77 00 00 00 25 00 73 00 5c 00 2a 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: High
        $x_1_3 = "C:\\Users\\Anton\\Documents" ascii //weight: 1
        $x_1_4 = "8d8f9528-24b0-11e5-ad78-3c970e317c6d" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

