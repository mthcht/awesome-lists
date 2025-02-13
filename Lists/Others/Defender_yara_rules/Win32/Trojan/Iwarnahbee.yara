rule Trojan_Win32_Iwarnahbee_A_2147637367_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Iwarnahbee.A"
        threat_id = "2147637367"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Iwarnahbee"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {c7 45 fc 08 00 00 00 6a 49 8d 45 80 50 ff 15 ?? ?? 40 00 6a 20 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? 40 00 6a 57 8d 95 ?? ?? ff ff 52 ff 15 ?? ?? 40 00 6a 61 8d 85 ?? ?? ff ff 50 ff 15 ?? ?? 40 00 6a 6e 8d 8d ?? ?? ff ff 51 ff 15 ?? ?? 40 00 6a 6e 8d 95 ?? ?? ff ff 52}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

