rule Ransom_Win32_Lolkek_PA_2147758756_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Lolkek.PA!MTB"
        threat_id = "2147758756"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolkek"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {83 f8 40 73 ?? 8b 45 ?? 41 8a 04 10 8b 55 ?? 32 04 32 8b 55 ?? 88 02 42 8b 45 ?? 40 89 55 ?? 89 45 ?? 3b c7 72}  //weight: 5, accuracy: Low
        $x_5_2 = "CRYPTO LOCKER" ascii //weight: 5
        $x_1_3 = ".lolkek" wide //weight: 1
        $x_1_4 = "LOLKEK.txt" wide //weight: 1
        $x_1_5 = "Read_Me.txt" wide //weight: 1
        $x_1_6 = "All your files, documents, photos, databases and other important files are encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

