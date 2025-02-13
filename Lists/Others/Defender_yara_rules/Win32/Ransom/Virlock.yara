rule Ransom_Win32_Virlock_B_2147741479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Virlock.B"
        threat_id = "2147741479"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {e9 00 00 00 00 81 ec ?? ?? ?? ?? be ?? ?? ?? ?? bf}  //weight: 5, accuracy: Low
        $x_5_2 = {e9 00 00 00 00 89 07 8b f8 8b df 90 b9 ?? ?? ?? ?? ba ?? ?? ?? ?? e9 ?? ?? ?? ?? c3}  //weight: 5, accuracy: Low
        $x_5_3 = {e9 00 00 00 00 0f 85 ?? ?? ?? ?? ff d3 81 c4 ?? ?? ?? ?? e9 ?? ?? ?? ?? 8a 06 32 c2 88 07 90 42 90 46 47 90 49 90 83 f9 00 e9 ?? ?? ff ff cc cc}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_Virlock_C_2147741973_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Virlock.C"
        threat_id = "2147741973"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Virlock"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = {e9 00 00 00 00 88 07 90 42 90 46 90 47 90 49 90 83 f9 00 90 0f 85 ?? ?? ?? ?? e9 ?? ?? ?? ?? 81 ec ?? ?? ?? ?? be ?? ?? ?? ?? bf ?? ?? ?? ?? e9}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

