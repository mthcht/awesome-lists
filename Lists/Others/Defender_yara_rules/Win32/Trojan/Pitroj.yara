rule Trojan_Win32_Pitroj_A_2147719213_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pitroj.A"
        threat_id = "2147719213"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pitroj"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Blackholec" ascii //weight: 1
        $x_1_2 = "capture_screent" ascii //weight: 1
        $x_1_3 = "Microsoft Product Defender.exe" ascii //weight: 1
        $x_1_4 = "virus.py" ascii //weight: 1
        $x_1_5 = "seq_data.pyt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

