rule Trojan_Win32_Capfetox_A_2147808598_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Capfetox.A"
        threat_id = "2147808598"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Capfetox"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "101"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "powershell" wide //weight: 100
        $x_1_2 = "iex" wide //weight: 1
        $x_1_3 = "downloadstring(" wide //weight: 1
        $x_1_4 = "downloadfile(" wide //weight: 1
        $x_1_5 = " -enc" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

