rule Ransom_Win32_MowareHFD_A_2147722800_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/MowareHFD.A!rsm"
        threat_id = "2147722800"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "MowareHFD"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "500"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "MoWare_H.F.D.My" ascii //weight: 100
        $x_100_2 = "__ENCAddToList" ascii //weight: 100
        $x_100_3 = "HFD/gen.php" wide //weight: 100
        $x_100_4 = "MRxC0DER@proton" wide //weight: 100
        $x_100_5 = "MoWare H.F.D.exe" wide //weight: 100
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

