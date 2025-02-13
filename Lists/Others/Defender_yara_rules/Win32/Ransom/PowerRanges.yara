rule Ransom_Win32_PowerRanges_A_2147853359_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PowerRanges.A!ibt"
        threat_id = "2147853359"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PowerRanges"
        severity = "Critical"
        info = "ibt: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "megazord_xi-1\\Windows\\x86_64-pc-windows-msvc\\debug\\deps\\megazord.pdb" ascii //weight: 1
        $x_1_2 = "megazord::lock" ascii //weight: 1
        $x_1_3 = "powerranges" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

