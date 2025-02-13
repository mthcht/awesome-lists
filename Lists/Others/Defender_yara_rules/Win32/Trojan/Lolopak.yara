rule Trojan_Win32_Lolopak_A_2147745203_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Lolopak.A!MSR"
        threat_id = "2147745203"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Lolopak"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b9 ff ff 0f 00 6a 00 89 2c 24 33 ed 33 ab ?? ?? ?? ?? 8b c5 5d 68 ?? ?? ?? ?? 8f 83 ?? ?? ?? ?? 21 8b ?? ?? ?? ?? 33 83 ?? ?? ?? ?? ff e0}  //weight: 1, accuracy: Low
        $x_1_2 = "msimg32.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

