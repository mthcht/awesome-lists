rule Trojan_Win32_PShellCob_SA_2147909961_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PShellCob.SA"
        threat_id = "2147909961"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PShellCob"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "New-Object IO.MemoryStream(,[Convert]::FromBase64String" wide //weight: 10
        $x_10_2 = ";IEX (New-Object IO.StreamReader(New-Object IO.Compression.GzipStream" wide //weight: 10
        $x_10_3 = "[IO.Compression.CompressionMode]::Decompress))).ReadToEnd();" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

