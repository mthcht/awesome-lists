rule Trojan_Win32_rundll32Url_A_2147967968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/rundll32Url.A"
        threat_id = "2147967968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "rundll32Url"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rundll32 \\\\" wide //weight: 5
        $x_5_2 = "rundll32.exe \\\\" wide //weight: 5
        $n_5_3 = "vmware-dem-fta-stub.dll" wide //weight: -5
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

