rule Trojan_Win32_Regmbu_2147607874_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Regmbu"
        threat_id = "2147607874"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Regmbu"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "cas.com/search.php?q={searchTerms}&pagina=1&rxp=20" ascii //weight: 4
        $x_2_2 = "SearchScopes\\{A34587234-AWER-3256-5TY6-12EDERGTY568}" ascii //weight: 2
        $x_1_3 = "1oftware\\Microsoft\\Internet Explorer\\1earch1copes" ascii //weight: 1
        $x_1_4 = "http://www.mbu1ca1.com/indexp.php?id=" ascii //weight: 1
        $x_1_5 = {42 47 20 57 69 6e 64 6f 77 73 32 00 49 45 58 50 4c 4f 52 45 52 2e 65 78 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_4_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

