rule Worm_Win32_Decoy_2147594579_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Decoy"
        threat_id = "2147594579"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Decoy"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "63"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "karena kami tidak ingin menyakiti data dan privasi anda" wide //weight: 10
        $x_10_2 = "Cah-Cah TI UNSIQ" wide //weight: 10
        $x_10_3 = "Word.Document.8\\shell\\Open\\command" wide //weight: 10
        $x_10_4 = "I75-D2\\dkernel.exe" wide //weight: 10
        $x_10_5 = "Tampungan" wide //weight: 10
        $x_10_6 = "formUtama" ascii //weight: 10
        $x_1_7 = "\\virus d2\\DE2.vbp" wide //weight: 1
        $x_1_8 = "GetWindowsDirectoryA" ascii //weight: 1
        $x_1_9 = "FindFirstFileA" ascii //weight: 1
        $x_1_10 = "FindNextFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_10_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

