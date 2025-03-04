rule Trojan_Win32_VBCrypt_YL_2147743248_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBCrypt.YL!MSR"
        threat_id = "2147743248"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBCrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rI8zVOpfz3nynM55389PgsyC2YLWuD0VNf79" wide //weight: 1
        $x_1_2 = "7.08.0003" wide //weight: 1
        $x_1_3 = "hHs2hHsDhHsXhHsjhHs" ascii //weight: 1
        $x_1_4 = "Gs8LHszJHs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_VBCrypt_YA_2147743604_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/VBCrypt.YA!MSR"
        threat_id = "2147743604"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "VBCrypt"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "gIEF.exe" wide //weight: 1
        $x_1_2 = "TSONera" wide //weight: 1
        $x_1_3 = "EfVrpt20lYNepM43" wide //weight: 1
        $x_1_4 = "dcNJtDcK1oNrG58" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

