rule TrojanDropper_Win32_Aenjaris_AMTB_2147964534_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/Aenjaris!AMTB"
        threat_id = "2147964534"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "Aenjaris"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1111ProgStart.name" ascii //weight: 1
        $x_1_2 = "33333.exe" ascii //weight: 1
        $x_1_3 = "8hE.9VP" ascii //weight: 1
        $x_1_4 = "4sV.JX3" ascii //weight: 1
        $x_1_5 = "uuu%ssswttr" ascii //weight: 1
        $x_1_6 = "yqe{yqeyyqeyyqevyqevytevyteyyvcyyuCt{t" ascii //weight: 1
        $n_100_7 = "Uninst.exe" ascii //weight: -100
        $n_100_8 = "Uninstaller.exe" ascii //weight: -100
        $n_100_9 = "Uninstal.exe" ascii //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

