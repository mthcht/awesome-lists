rule Ransom_Win32_Philadelphia_A_2147733495_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Philadelphia.A!bit"
        threat_id = "2147733495"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Philadelphia"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pd4ta.dat" wide //weight: 1
        $x_1_2 = "L0F1dG9JdDNFeGVjdXRlU2NyaXB0" wide //weight: 1
        $x_1_3 = "FILESETATTRIB ( @AUTOITEXE , \"+H\" )" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

