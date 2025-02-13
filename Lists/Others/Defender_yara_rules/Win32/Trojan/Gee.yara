rule Trojan_Win32_Gee_B_2147648661_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Gee.B"
        threat_id = "2147648661"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Gee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {49 45 48 6f 73 74 32 53 65 72 76 69 63 65 73 (00 ff ff ff ff 7d 18 40 00 91|00 49 45 48 6f 73 74 32 20 53 65 72 76 69 63)}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

