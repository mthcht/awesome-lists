rule Ransom_Win32_NefilimGo_PA_2147782991_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NefilimGo.PA!MTB"
        threat_id = "2147782991"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NefilimGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".lock" ascii //weight: 1
        $x_1_2 = "Go build ID:" ascii //weight: 1
        $x_1_3 = "stoptheworld" ascii //weight: 1
        $x_1_4 = "main.SaveNote.func" ascii //weight: 1
        $x_1_5 = "main.FileSearch.func" ascii //weight: 1
        $x_1_6 = "main.getdrives" ascii //weight: 1
        $x_1_7 = "main.UnixFile" ascii //weight: 1
        $x_1_8 = "main.GenerateRandomBytes" ascii //weight: 1
        $x_1_9 = "path/filepath.SkipDir" ascii //weight: 1
        $x_1_10 = "unreachableuserenv.dll" ascii //weight: 1
        $x_1_11 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (9 of ($x*))
}

rule Ransom_Win32_NefilimGo_PB_2147793167_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/NefilimGo.PB!MTB"
        threat_id = "2147793167"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "NefilimGo"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = ".LEAKS" ascii //weight: 1
        $x_1_2 = "Go build ID: \"" ascii //weight: 1
        $x_1_3 = "LEAKS!!!DANGER.txt" ascii //weight: 1
        $x_1_4 = ".IsEncryptedPEMBlock" ascii //weight: 1
        $x_1_5 = "at  fp= is  lr: of  on  pc= sp: sp=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

