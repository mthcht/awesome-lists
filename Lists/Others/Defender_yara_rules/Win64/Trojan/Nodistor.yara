rule Trojan_Win64_Nodistor_A_2147964381_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Nodistor.A"
        threat_id = "2147964381"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Nodistor"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {41 72 65 46 69 6c 65 41 70 69 73 41 4e 53 49 ?? ?? ?? 43 6c 6f 73 65 48 61 6e 64 6c 65 0d 00 5f 03 00 5f 04 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

