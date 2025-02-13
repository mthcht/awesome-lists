rule DoS_Win32_Pokanti_A_2147617985_0
{
    meta:
        author = "defender2yara"
        detection_name = "DoS:Win32/Pokanti.A"
        threat_id = "2147617985"
        type = "DoS"
        platform = "Win32: Windows 32-bit platform"
        family = "Pokanti"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Anti Pornografi" wide //weight: 1
        $x_1_2 = "~ INDONESIAN VX ZONE ~" wide //weight: 1
        $x_1_3 = "VirBok3p" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

