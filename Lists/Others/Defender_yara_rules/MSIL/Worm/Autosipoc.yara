rule Worm_MSIL_Autosipoc_A_2147645821_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:MSIL/Autosipoc.A"
        threat_id = "2147645821"
        type = "Worm"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Autosipoc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "pcport\\autocopis - Copy" ascii //weight: 1
        $x_1_2 = "terseras carpetas" wide //weight: 1
        $x_1_3 = "$RECYCLE.BIN" wide //weight: 1
        $x_1_4 = "HKEY_CURRENT_USER\\Software\\Ares" wide //weight: 1
        $x_1_5 = "Folder.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

