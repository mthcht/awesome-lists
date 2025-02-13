rule Worm_Win32_Korpu_A_2147601278_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Korpu.A"
        threat_id = "2147601278"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Korpu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_6_1 = "\\Dodo\\Penting\\Code\\v\\r\\Ronkor.vbp" wide //weight: 6
        $x_2_2 = "PersistMoniker=file://r0nk0r\\Folder.htt" wide //weight: 2
        $x_2_3 = "\\r0nk0r\\Poto wow.exe.exe" wide //weight: 2
        $x_2_4 = "Apa yang kulakukan tak dapat kumaafkan" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_6_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

