rule Trojan_Win32_DinaBot_SA_2147897576_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DinaBot.SA"
        threat_id = "2147897576"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DinaBot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "rundll32.exe" wide //weight: 1
        $x_1_2 = {73 00 68 00 65 00 6c 00 6c 00 33 00 32 00 2e 00 64 00 6c 00 6c 00 [0-5] 23 00}  //weight: 1, accuracy: Low
        $x_1_3 = "syswow64\\explorer.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

