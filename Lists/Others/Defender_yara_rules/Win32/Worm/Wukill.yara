rule Worm_Win32_Wukill_A_2147583560_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Wukill@mm.gen!A"
        threat_id = "2147583560"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Wukill"
        severity = "Critical"
        info = "mm: mass mailer worm"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {77 75 6b 69 6c 6c 00 58 67 74 72 61 79}  //weight: 1, accuracy: High
        $x_1_2 = "*\\AD:\\Program Files\\Microsoft Visual Studio\\VB98\\lhw\\XDD\\XDD" wide //weight: 1
        $x_1_3 = "END+noWSH+" wide //weight: 1
        $x_1_4 = "\\Xgtray.vbp" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

