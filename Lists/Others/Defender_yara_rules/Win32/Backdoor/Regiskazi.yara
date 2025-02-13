rule Backdoor_Win32_Regiskazi_A_2147693313_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Regiskazi.A"
        threat_id = "2147693313"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Regiskazi"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "&kart=KotuKart&core=2&mhz=YAVAS" ascii //weight: 4
        $x_4_2 = "Referer: WindowsXP-32-Nonti-KotuKart-2-YAVAS" ascii //weight: 4
        $x_2_3 = "fdsfdsfdsf\\fsdfdsf" ascii //weight: 2
        $x_2_4 = "!calistir" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

