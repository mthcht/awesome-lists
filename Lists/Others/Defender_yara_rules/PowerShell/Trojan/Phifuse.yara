rule Trojan_PowerShell_Phifuse_B_2147726059_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/Phifuse.B"
        threat_id = "2147726059"
        type = "Trojan"
        platform = "PowerShell: "
        family = "Phifuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\"IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:\\\\Software" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

