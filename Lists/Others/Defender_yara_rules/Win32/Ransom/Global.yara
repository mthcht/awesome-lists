rule Ransom_Win32_Global_B_2147961125_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Global.B"
        threat_id = "2147961125"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Global"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "-skip-local" wide //weight: 1
        $x_1_2 = "unmounting drive %c: after encryption" wide //weight: 1
        $x_1_3 = "got no path, encrypting all drives." wide //weight: 1
        $x_2_4 = {00 78 63 72 79 ?? ?? ?? ?? ?? ?? ?? 64 74 65 64 ?? ?? ?? ?? ?? ?? ?? 6e 6f 74 73 ?? ?? ?? ?? ?? ?? ?? 74 69 6c 6c ?? ?? ?? ?? ?? ?? ?? 5f 61 6d 61 ?? ?? ?? ?? ?? ?? ?? 7a 69 6e 67}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            (all of ($x*))
        )
}

