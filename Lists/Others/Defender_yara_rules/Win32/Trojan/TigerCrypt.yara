rule Trojan_Win32_TigerCrypt_B_2147916847_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/TigerCrypt.B!dha"
        threat_id = "2147916847"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "TigerCrypt"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "100"
        strings_accuracy = "Low"
    strings:
        $x_100_1 = {bf d0 07 00 00 66 90 6a 40 68 00 10 00 00 68 10 27 00 00 6a 00 ff ?? 6a 01 8b f0 ff 15 ?? ?? ?? ?? 68 00 80 00 00 6a 00 56 ff}  //weight: 100, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

