rule Worm_Win32_Havkiez_A_2147695148_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Havkiez.A"
        threat_id = "2147695148"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Havkiez"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "open = New Document.exe" wide //weight: 1
        $x_1_2 = "config_.com" wide //weight: 1
        $x_1_3 = "Sys_.com" wide //weight: 1
        $x_1_4 = "startupfolder.com" wide //weight: 1
        $x_1_5 = "mscalc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

