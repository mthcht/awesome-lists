rule Trojan_Win32_Catchmanloader_2147752218_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Catchmanloader!dha"
        threat_id = "2147752218"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Catchmanloader"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "c:\\windows\\WinInstall.log" ascii //weight: 2
        $x_2_2 = "mB3JhlrjUxL1YJcn" ascii //weight: 2
        $x_1_3 = {69 6e 6a 65 63 74 2e 64 6c 6c 00 64 6c 6c 66 75 6e}  //weight: 1, accuracy: High
        $x_1_4 = "Failed to inject the DLL" ascii //weight: 1
        $x_1_5 = "ReflectiveDLLInjection-master\\Release\\inject.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

