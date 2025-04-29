rule Trojan_PowerShell_ROKRat_RPA_2147940272_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:PowerShell/ROKRat.RPA!MTB"
        threat_id = "2147940272"
        type = "Trojan"
        platform = "PowerShell: "
        family = "ROKRat"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "243"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "powershell.exe" wide //weight: 10
        $x_100_2 = "-Recurse *.* -File | where {$_.extension -in $" wide //weight: 100
        $x_10_3 = "| where-object {$_.length -eq 0x" wide //weight: 10
        $x_10_4 = "New-Object System.IO.FileStream($" wide //weight: 10
        $x_100_5 = "[System.IO.FileMode]::Open, [System.IO.FileAccess]::Read);$lnkFile.Seek(0x" wide //weight: 100
        $x_10_6 = "[System.IO.SeekOrigin]::Begin)" wide //weight: 10
        $x_1_7 = "-Match 'System32'" wide //weight: 1
        $x_1_8 = "-Match 'Program Files'" wide //weight: 1
        $x_1_9 = "=@('.lnk')" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

