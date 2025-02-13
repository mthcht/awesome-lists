rule Trojan_Win32_ReedBed_ZZ_2147932660_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/ReedBed.ZZ"
        threat_id = "2147932660"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "ReedBed"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "103"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "\\SOFTWARE\\TitanPlus" wide //weight: 100
        $x_1_2 = "reg" wide //weight: 1
        $x_1_3 = " add " wide //weight: 1
        $x_1_4 = " /t REG_SZ /d " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

