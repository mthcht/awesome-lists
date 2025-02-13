rule TrojanDownloader_MSIL_Waultca_A_2147740855_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Waultca.A!dha"
        threat_id = "2147740855"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Waultca"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "6d9e9d9d-b45a-4164-a864-0d029120f182" ascii //weight: 5
        $x_4_2 = "microsoft.updatemeltdownkb7234.com" wide //weight: 4
        $x_4_3 = "codewizard.ml/productivity/" wide //weight: 4
        $x_3_4 = "fag02wu" wide //weight: 3
        $x_2_5 = "CurrentPrxSet" wide //weight: 2
        $x_1_6 = "form-data; name=\"{0}\"; filename=\"{1}\"" wide //weight: 1
        $x_1_7 = "!upl " wide //weight: 1
        $x_1_8 = "whoami & systeminfo & ipconfig /all & arp /a" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((1 of ($x_3_*) and 2 of ($x_1_*))) or
            ((1 of ($x_3_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_1_*))) or
            ((1 of ($x_4_*) and 1 of ($x_2_*))) or
            ((1 of ($x_4_*) and 1 of ($x_3_*))) or
            ((2 of ($x_4_*))) or
            ((1 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_MSIL_Waultca_B_2147744101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:MSIL/Waultca.B!dha"
        threat_id = "2147744101"
        type = "TrojanDownloader"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Waultca"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "1df52441-98f3-4546-a63c-d1d4ceb9d241" ascii //weight: 4
        $x_4_2 = "a7d94843-0bdf-4675-9735-bf75857331fb" ascii //weight: 4
        $x_2_3 = "Windows Remote Management(WS - Managment)" wide //weight: 2
        $x_2_4 = "WSMan Provider Service" wide //weight: 2
        $x_2_5 = "C2D9F6B63DDE5FAAC251EAE2D9687C4F379355DBC7801339D6FAD91B666FBE6F" wide //weight: 2
        $x_2_6 = "450A11B862C2DA9F3AB2506E775B5037ED48E38915D539A15ECE6AFCC5842326" wide //weight: 2
        $x_2_7 = "2E4B7C022329E5C21E47D55E8916F6AF852AABBBD1798F9E16985F22A8056646" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_2_*))) or
            ((1 of ($x_4_*))) or
            (all of ($x*))
        )
}

