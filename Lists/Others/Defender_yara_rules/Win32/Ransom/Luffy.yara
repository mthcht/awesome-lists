rule Ransom_Win32_Luffy_A_2147960431_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Luffy.A!AMTB"
        threat_id = "2147960431"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Luffy"
        severity = "Critical"
        info = "AMTB: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Luffy-Enc.pdb" ascii //weight: 1
        $x_1_2 = "1337_salt!" ascii //weight: 1
        $x_1_3 = "TuProyecto.imagen.png" ascii //weight: 1
        $x_1_4 = "TuProyecto.drop.exe" ascii //weight: 1
        $x_1_5 = ".luffy" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

