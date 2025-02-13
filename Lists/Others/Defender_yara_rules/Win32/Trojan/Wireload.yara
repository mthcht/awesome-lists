rule Trojan_Win32_Wireload_A_2147902368_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Wireload.A!dha"
        threat_id = "2147902368"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Wireload"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {48 89 5c 24 10 48 89 74 24 18 55 57 41 56 48 8d 6c 24 80 48 81 ec 80 01 00 00 e8 ?? ?? ?? ?? ba fc 25 72 3b 48 8b c8 48 8b f8 e8 ?? ?? ?? ?? ba 8a f8 c4 02 48 89 44 24 38 48 8b cf e8}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

