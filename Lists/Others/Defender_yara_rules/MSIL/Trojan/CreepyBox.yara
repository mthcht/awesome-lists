rule Trojan_MSIL_CreepyBox_A_2147818393_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CreepyBox.A!dha"
        threat_id = "2147818393"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CreepyBox"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "/uploads created!" wide //weight: 1
        $x_1_2 = "/cmdResult created!" wide //weight: 1
        $x_1_3 = "/downloadsResulat created!" wide //weight: 1
        $x_1_4 = "/MissingUploadParameterLine" wide //weight: 1
        $x_1_5 = "/MissingDownloadParameter.txt" wide //weight: 1
        $x_3_6 = "UBnLjCsGLFgAAAAAAAAAAYUsNaoRKmGN5-R0ecJk76DwdtrjiPUmIgB_6fmR1SEu" wide //weight: 3
        $x_3_7 = "Yew-rgFAtM0AAAAAAAAAAdxiG9HkchNZgdOmNz6N6duFDUBmDweVudXi2_KKFSVO" wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_3_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_CreepyBox_B_2147818394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CreepyBox.B!dha"
        threat_id = "2147818394"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CreepyBox"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell -Command \"$c1 = '" wide //weight: 1
        $x_2_2 = "-Command '$shortcut = (New-Object -comObject WScript.Shell).CreateShortcut($c1);$shortcut.TargetPath = $c2;$shortcut.Save()" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

