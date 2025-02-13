rule Trojan_Win64_TreeTrunk_B_2147828394_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/TreeTrunk.B!dha"
        threat_id = "2147828394"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "TreeTrunk"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "DosCommandThread" ascii //weight: 1
        $x_1_2 = "/index.jsp" wide //weight: 1
        $x_1_3 = "WinDDK.7600" wide //weight: 1
        $x_1_4 = "71473D04BAD1408998" wide //weight: 1
        $x_1_5 = "73852A" wide //weight: 1
        $x_1_6 = "74F585369233E267B3D8FEA7" wide //weight: 1
        $x_1_7 = "7657F1C1B4BDD2B9C576" wide //weight: 1
        $x_1_8 = "7657F1C1B4B7A57412F5C558" wide //weight: 1
        $x_1_9 = "7657F1C1B5D2FFC4F55A" wide //weight: 1
        $x_1_10 = "7657F1C1A5FA402D571F" wide //weight: 1
        $x_1_11 = "7775A90104A26B4FAE406D2705" wide //weight: 1
        $x_1_12 = "7775A90104A26B486D2E089255" wide //weight: 1
        $x_1_13 = "7775A906EC27" wide //weight: 1
        $x_1_14 = "7775A906EC262E" wide //weight: 1
        $x_1_15 = "7775A90488695A0D89A56E" wide //weight: 1
        $x_1_16 = "7775A9122F94968A62F9" wide //weight: 1
        $x_1_17 = "79DA73E2E52C648FBDA433E96EFA4DBDE6" wide //weight: 1
        $x_1_18 = "79DA73E2E52C648FBDA433EE75F0D36574" wide //weight: 1
        $x_1_19 = "7B31C9A56B15AEA8FC6032" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

