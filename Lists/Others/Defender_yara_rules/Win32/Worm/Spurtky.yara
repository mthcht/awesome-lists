rule Worm_Win32_Spurtky_A_2147653545_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Spurtky.A"
        threat_id = "2147653545"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Spurtky"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Turk-Spy" ascii //weight: 1
        $x_1_2 = "kurban_isim" ascii //weight: 1
        $x_1_3 = "msnpwds" ascii //weight: 1
        $x_1_4 = "CIE7Passwords" ascii //weight: 1
        $x_1_5 = "IsInSandboxes" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

