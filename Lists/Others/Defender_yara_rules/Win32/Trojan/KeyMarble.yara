rule Trojan_Win32_KeyMarble_2147728575_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KeyMarble"
        threat_id = "2147728575"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KeyMarble"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SOFTWARE\\Microsoft\\WABE" wide //weight: 1
        $x_1_2 = "212.143.21.43" wide //weight: 1
        $x_1_3 = "104.194.160.59" wide //weight: 1
        $x_1_4 = "100.43.153.60" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

