rule Trojan_Win32_Reechrot_A_2147631026_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Reechrot.A"
        threat_id = "2147631026"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Reechrot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {33 c9 3d 00 (50|40) 01 00 0f 94 c1 f7 d9}  //weight: 2, accuracy: Low
        $x_2_2 = {eb 0e 66 05 01 00 0f 80 c7 00 00 00 66 89 46 3c 66 8b 76 3c 66 83 fe 01 75 09 c7 45 bc ?? ?? ?? ?? eb 14 66 83 fe 02}  //weight: 2, accuracy: Low
        $x_1_3 = "Terbaru" ascii //weight: 1
        $x_1_4 = "Si GASAK has been Disabled by The Creator!! Cheers!! ;)" wide //weight: 1
        $x_1_5 = "rundll32.exe user.exe,exitwindows" wide //weight: 1
        $x_1_6 = "Startup\\autoex.bat" wide //weight: 1
        $x_1_7 = "phone.reg" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

