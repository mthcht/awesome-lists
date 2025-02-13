rule Spammer_Win32_Delf_Q_2147684816_0
{
    meta:
        author = "defender2yara"
        detection_name = "Spammer:Win32/Delf.Q"
        threat_id = "2147684816"
        type = "Spammer"
        platform = "Win32: Windows 32-bit platform"
        family = "Delf"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {4b 85 db 7c ?? 8b ?? ?? c1 e0 06 03 d8 89 ?? ?? 83 c7 06 83 ff 08 7c ?? 83 ef 08 8b cf 8b ?? ?? d3 eb 8b cf b8 01 00 00 00 d3 e0 50 8b ?? ?? 5a 8b ca 99 f7 f9 89 ?? ?? 81 e3 ff 00 00 80 79 08 4b 81 cb 00 ff ff ff 43}  //weight: 3, accuracy: Low
        $x_1_2 = "yZPCtg6Nx761Dc97Ehq" ascii //weight: 1
        $x_1_3 = "BxnVzubTAwnYB2nVzNqUy86T" ascii //weight: 1
        $x_2_4 = "2altrfkindysadvnqw3nerasdf" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

