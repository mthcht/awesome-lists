rule Trojan_Win32_Malachite_A_2147724735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Malachite.A!bit"
        threat_id = "2147724735"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Malachite"
        severity = "Critical"
        info = "bit: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "botnets\\infernal_machine2\\src\\infect.vcxproj" ascii //weight: 1
        $x_1_2 = "copy ..\\release\\vir.bin bin\\drop.bin" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

