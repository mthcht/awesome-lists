rule TrojanSpy_MSIL_Cuokja_A_2147688492_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:MSIL/Cuokja.A"
        threat_id = "2147688492"
        type = "TrojanSpy"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Cuokja"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\systems32\\systemdll32.exe" wide //weight: 1
        $x_1_2 = "\\tempupdater" wide //weight: 1
        $x_1_3 = "!!! :: Torrentmove.CoM Login" wide //weight: 1
        $x_1_4 = "Dota Password" wide //weight: 1
        $x_1_5 = "Pantip Password" wide //weight: 1
        $x_1_6 = "\\cookja" wide //weight: 1
        $x_1_7 = "createdirpic" ascii //weight: 1
        $x_1_8 = "delcook" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

