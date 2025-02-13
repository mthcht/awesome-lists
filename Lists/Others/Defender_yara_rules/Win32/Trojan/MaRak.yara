rule Trojan_Win32_MaRak_B_2147930886_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MaRak.B"
        threat_id = "2147930886"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MaRak"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "[io.file]::readalltext(" wide //weight: 1
        $x_1_3 = ".cmd') -split" wide //weight: 1
        $x_1_4 = ";iex ($" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

