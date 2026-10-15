rule Ransom_Win32_RansomSimple_AMTB_2147980361_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/RansomSimple!AMTB"
        threat_id = "2147980361"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "RansomSimple"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "RansomSimple.pdb" ascii //weight: 2
        $x_2_2 = "RansomSimpleSalt2024!" ascii //weight: 2
        $x_1_3 = ".LOCKED" ascii //weight: 1
        $x_1_4 = "README_ENCRYPTED.txt" ascii //weight: 1
        $x_1_5 = "SYSTEM PERMANENTLY LOCKED" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

