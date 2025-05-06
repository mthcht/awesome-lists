rule TrojanDownloader_Win32_MshtaAbuse_A_2147811392_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/MshtaAbuse.A"
        threat_id = "2147811392"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "http://0x" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_MshtaAbuse_B_2147811393_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/MshtaAbuse.B"
        threat_id = "2147811393"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta" wide //weight: 1
        $x_1_2 = "http://0" wide //weight: 1
        $n_1000_3 = "msedgewebview2.exe" wide //weight: -1000
        $n_1000_4 = "if false == false echo" wide //weight: -1000
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_MshtaAbuse_C_2147811629_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/MshtaAbuse.C"
        threat_id = "2147811629"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "MshtaAbuse"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "mshta http://" wide //weight: 1
        $x_1_2 = "mshta https://" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

