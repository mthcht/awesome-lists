rule Trojan_Win32_Rundll32Url_A_2147967968_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rundll32Url.A"
        threat_id = "2147967968"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rundll32Url"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "rundll32 \\\\" wide //weight: 5
        $x_5_2 = "rundll32.exe \\\\" wide //weight: 5
        $n_20_3 = "vmware-dem-fta-stub.dll" wide //weight: -20
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_Rundll32Url_B_2147969951_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rundll32Url.B"
        threat_id = "2147969951"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rundll32Url"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 2e 00 65 00 78 00 65 00 20 00 5c 00 5c 00 2d 7f 7f 01 5c 2e 00 2d ff ff 01 5c 5c 00}  //weight: 5, accuracy: Low
        $x_5_2 = {72 00 75 00 6e 00 64 00 6c 00 6c 00 33 00 32 00 20 00 5c 00 5c 00 2d 7f 7f 01 5c 2e 00 2d ff ff 01 5c 5c 00}  //weight: 5, accuracy: Low
        $n_20_3 = "vmware-dem-fta-stub.dll" wide //weight: -20
        $x_1_4 = "507196c6-5a2b-41cc-a7d1-8b222f0136f7" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

