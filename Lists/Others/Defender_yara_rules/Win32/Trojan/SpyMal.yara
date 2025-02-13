rule Trojan_Win32_SpyMal_A_2147734379_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SpyMal.A"
        threat_id = "2147734379"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SpyMal"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "starikl.pdb" ascii //weight: 1
        $x_1_2 = "hadcxaz.pdb" ascii //weight: 1
        $x_1_3 = "yabesar.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

