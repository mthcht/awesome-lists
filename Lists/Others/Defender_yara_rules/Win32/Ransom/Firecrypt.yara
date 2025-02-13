rule Ransom_Win32_Firecrypt_A_2147719230_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Firecrypt.A"
        threat_id = "2147719230"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Firecrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".firecrypt" wide //weight: 10
        $x_10_2 = {2e 00 64 00 6f 00 63 00 78 00 00 09 2e 00 63 00 73 00 76 00 00 09 2e 00 73 00 71 00 6c 00}  //weight: 10, accuracy: High
        $x_10_3 = "\\SysWin32" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Firecrypt_A_2147719230_1
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Firecrypt.A"
        threat_id = "2147719230"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Firecrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "\\BleedGreen.pdb" ascii //weight: 10
        $x_10_2 = "AES256 RansomeWare" wide //weight: 10
        $x_10_3 = "DDoser... (Because" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Firecrypt_A_2147719230_2
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Firecrypt.A"
        threat_id = "2147719230"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Firecrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = ".firecrypt" wide //weight: 10
        $x_10_2 = {2e 00 64 00 6f 00 63 00 78 00 00 09 2e 00 63 00 73 00 76 00 00 09 2e 00 73 00 71 00 6c 00}  //weight: 10, accuracy: High
        $x_10_3 = "\\SysWin32" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

