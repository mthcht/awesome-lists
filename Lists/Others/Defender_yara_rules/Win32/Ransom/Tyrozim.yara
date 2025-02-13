rule Ransom_Win32_Tyrozim_A_2147726242_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Tyrozim.A"
        threat_id = "2147726242"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Tyrozim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Z:\\Shadow\\SilentSpring\\Release\\$_1.pdb" ascii //weight: 1
        $x_1_2 = {0f a2 89 c7 31 c0 81 fb 47 65 6e 75 0f 95 c0 89 c5 81 fa 69 6e 65 49 0f 95 c0 09 c5 81 f9 6e 74 65 6c 0f 95 c0 09 c5 0f 84}  //weight: 1, accuracy: High
        $x_1_3 = {81 fb 41 75 74 68 0f 95 c0 89 c6 81 fa 65 6e 74 69 0f 95 c0 09 c6 81 f9 63 41 4d 44 0f 95 c0 09 c6 0f 85}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

