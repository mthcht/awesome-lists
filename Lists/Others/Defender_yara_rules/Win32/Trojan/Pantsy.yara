rule Trojan_Win32_Pantsy_A_2147744099_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Pantsy.A!dha"
        threat_id = "2147744099"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Pantsy"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "asm2pe.dll" ascii //weight: 1
        $x_1_2 = {6e 74 64 6c 6c 2e 64 6c 6c 00 4c 64 72 4c 6f 61 64 44 6c 6c}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

