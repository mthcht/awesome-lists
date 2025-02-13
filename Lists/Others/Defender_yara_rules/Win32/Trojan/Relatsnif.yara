rule Trojan_Win32_Relatsnif_A_2147919071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Relatsnif.A"
        threat_id = "2147919071"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Relatsnif"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {63 00 75 00 72 00 6c 00 [0-16] 20 00 2d 00 6f 00 20 00}  //weight: 2, accuracy: Low
        $x_2_2 = "curse-breaker.org" wide //weight: 2
        $x_1_3 = "files/installer.dll" wide //weight: 1
        $x_1_4 = "\\AppData\\Roaming\\IFInstaller.dll" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

