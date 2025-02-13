rule Trojan_Win32_Luder_C_2147576931_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Luder.C"
        threat_id = "2147576931"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Luder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "13"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = "632tr67238r2gf623gfy2uigfyufigyewgfeyf" ascii //weight: 3
        $x_3_2 = "3i27fgi298f7gfiuewgfugefuygixnygifyxugifxy43gx43f" ascii //weight: 3
        $x_3_3 = "muco1" ascii //weight: 3
        $x_1_4 = "Rio Grande" ascii //weight: 1
        $x_2_5 = "Alonzo" ascii //weight: 2
        $x_10_6 = {55 8b ec 81 c4 fc fe ff ff 8d 05 ?? ?? ?? 00 e8 ?? ?? ?? 00 50 8d 85 fc fe ff ff 50 68 04 01 00 00 e8 ?? ?? ?? 00 90 e8 ?? ?? ?? 00 59 33 c1 60 eb 0b 33 c0 21 36 21 16 2c 58 2c 21 16 8b cb c1 e8 02 f7 db 61 8b d0 ff 75 08 52 8d 15 14 11 40 00 52 87 d2 8d 95 fc fe ff ff 52 8d 15 ?? ?? ?? 00 c1 c0 0c ff d2 c9 c2 04 00}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((1 of ($x_10_*) and 1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Luder_D_2147582086_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Luder.D"
        threat_id = "2147582086"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Luder"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {e2 fd 6a 44 8b ?? 83 ec 10 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? b8 1b e6 77 ff ?? 83 c4 54 33 ?? 64 8f ?? ?? 68 ?? ?? ?? ?? c3 68 ?? ?? ?? ?? 8b 44 24 10 8f 80 b8 00 00 00 33 c0 c3 43 3a 5c}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

