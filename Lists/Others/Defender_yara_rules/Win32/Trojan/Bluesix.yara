rule Trojan_Win32_Bluesix_A_2147677711_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Bluesix.A"
        threat_id = "2147677711"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Bluesix"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6a 00 6a 01 6a 02 a3 ?? ?? 40 00 66 c7 05 ?? ?? 40 00 02 00 e8 ?? ?? 00 00 6a 10 68 ?? ?? 40 00 50 a3 ?? ?? 40 00 e8 ?? 03 00 00 83 f8 ff 75 18 8b 15 ?? ?? 40 00 6a 10 68 ?? ?? 40 00 52 e8 ?? ?? 00 00 83 f8 ff 74 e8 a1 ?? ?? 40 00 6a 00 68 00 20 00 00 68 ?? ?? 40 00 50 e8 ?? 02 00 00 85 c0}  //weight: 1, accuracy: Low
        $x_1_2 = "ClientRandom[32]" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

