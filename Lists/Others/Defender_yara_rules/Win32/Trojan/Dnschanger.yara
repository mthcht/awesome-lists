rule Trojan_Win32_DNSChanger_DD_2147742392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DNSChanger.DD"
        threat_id = "2147742392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DNSChanger"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {68 00 74 00 74 00 70 00 73 00 3a 00 2f 00 2f 00 73 00 61 00 6c 00 74 00 6c 00 6f 00 67 00 [0-21] 2e 00 72 00 75 00 2f 00 6c 00 6f 00 67 00}  //weight: 1, accuracy: Low
        $x_1_2 = {68 74 74 70 73 3a 2f 2f 73 61 6c 74 6c 6f 67 [0-21] 2e 72 75 2f 6c 6f 67}  //weight: 1, accuracy: Low
        $x_1_3 = "CbyPINbMRBlWymr2" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

