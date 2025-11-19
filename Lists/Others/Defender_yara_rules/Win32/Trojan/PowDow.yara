rule Trojan_Win32_PowDow_DB_2147957737_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PowDow.DB!MTB"
        threat_id = "2147957737"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PowDow"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "Invoke-WebRequest -Uri 'https://" wide //weight: 10
        $x_10_2 = "iwr -Uri 'https://" wide //weight: 10
        $x_1_3 = ".msi' -OutFile $env:TEMP\\" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

