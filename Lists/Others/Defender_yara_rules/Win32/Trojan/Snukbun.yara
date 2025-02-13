rule Trojan_Win32_Snukbun_D_2147773772_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Snukbun.D!dha"
        threat_id = "2147773772"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Snukbun"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "schtasks" wide //weight: 10
        $x_1_2 = {63 00 68 00 72 00 6f 00 6d 00 65 00 90 00 02 00 02 00 75 00 70 00 64 00 61 00 74 00 65 00 2d 00}  //weight: 1, accuracy: High
        $x_1_3 = "chromeosservices-" wide //weight: 1
        $x_1_4 = "google-update-" wide //weight: 1
        $x_1_5 = "ieupdateservice" wide //weight: 1
        $x_1_6 = "sxwe534-cvns678-etezxa9" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

