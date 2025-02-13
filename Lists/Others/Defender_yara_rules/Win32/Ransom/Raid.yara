rule Ransom_Win32_Raid_A_2147726462_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Raid.A"
        threat_id = "2147726462"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Raid"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "ALL YOUR FILES ARE ENCRYPTED BY RAPID 2.0 RANSOMWARE" ascii //weight: 1
        $x_1_2 = "purchase a Rapid Decryptor" ascii //weight: 1
        $x_1_3 = "delete Rapid from your PC." ascii //weight: 1
        $x_1_4 = "supp1decr@cock.li" ascii //weight: 1
        $x_1_5 = "supp2decr@cock.li" ascii //weight: 1
        $x_1_6 = "we can decrypt only 1 file for free" ascii //weight: 1
        $x_1_7 = "Dont try to use third-party decryptor tools because it will destroy your files." ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

