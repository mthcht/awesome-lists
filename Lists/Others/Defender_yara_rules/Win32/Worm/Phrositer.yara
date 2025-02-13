rule Worm_Win32_Phrositer_2147601554_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Phrositer"
        threat_id = "2147601554"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Phrositer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "High"
    strings:
        $x_11_1 = "c:\\program files\\microsoft visual studio\\vb98\\vb6.olb" ascii //weight: 11
        $x_11_2 = {f5 00 00 00 00 05 06 00 3a 1c ff 49 00 fb ef 6c ff 0a 10 00 08 00 fd 6b fc fe fc f6 0c ff 35 6c ff 00 16}  //weight: 11, accuracy: High
        $x_2_3 = "Sephirot" ascii //weight: 2
        $x_1_4 = "regattack" ascii //weight: 1
        $x_1_5 = "infectdrive" ascii //weight: 1
        $x_1_6 = "g:\\kadaj.exe" ascii //weight: 1
        $x_2_7 = "shell\\Auto\\command=kadaj.exe" ascii //weight: 2
        $x_2_8 = "net localgroup administrators ronin /add" ascii //weight: 2
        $x_1_9 = "Smile, Doozo Yoroshiku" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_11_*) and 4 of ($x_1_*))) or
            ((2 of ($x_11_*) and 1 of ($x_2_*) and 2 of ($x_1_*))) or
            ((2 of ($x_11_*) and 2 of ($x_2_*))) or
            (all of ($x*))
        )
}

