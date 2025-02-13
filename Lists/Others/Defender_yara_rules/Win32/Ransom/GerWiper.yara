rule Ransom_Win32_GerWiper_A_2147741604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/GerWiper.A"
        threat_id = "2147741604"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "GerWiper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {8b 0c be 8b d1 c1 ea ?? 88 10 8b d1 c1 ea ?? 88 50 ?? 8b d1 c1 ea ?? 88 50 ?? 88 48 ?? 8b 4e 6c 47 c1 e9 ?? 83 c0 ?? 3b f9 72 d5}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

