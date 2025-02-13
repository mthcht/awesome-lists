rule TrojanDownloader_Win32_Dothemt_A_2147714855_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Dothemt.A"
        threat_id = "2147714855"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Dothemt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "N{d?u~g?p)c?t?.@u?w|u?" wide //weight: 1
        $x_2_2 = "i(s?u?o%:?#+#?t<u?h&m?r}.$`?t*s?s{n?-~r?n)h?u?g@n?r|i?.>d?n(n?#?t%s?b+s?v<r?#&h?o}c$f?w*.?o{i?o~??" wide //weight: 2
        $x_2_3 = "i}s$u?o*:?#{#?h~o?e)p?.?s@`?u|t?t>g?-(u?j?c%f?n+t?s<#?l&j?r}d$#?t*u?d{1?.~c?b)s?" wide //weight: 2
        $x_1_4 = {48 83 c8 fe 40 f7 d8 1a c0 24 fe fe c0 02 c3 88 04 3e eb 03 88 1c 3e 52 ff 75 f8 e8}  //weight: 1, accuracy: High
        $x_1_5 = {c7 45 f4 4e 74 64 6c c7 45 f8 6c 2e 64 6c 66 c7 45 fc 6c 00}  //weight: 1, accuracy: High
        $x_1_6 = {c7 45 e4 6d 61 74 69 c7 45 e8 6f 6e 50 72 c7 45 ec 6f 63 65 73 66 c7 45 f0 73 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            ((2 of ($x_2_*))) or
            (all of ($x*))
        )
}

