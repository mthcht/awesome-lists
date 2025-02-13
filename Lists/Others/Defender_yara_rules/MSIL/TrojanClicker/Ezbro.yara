rule TrojanClicker_MSIL_Ezbro_B_2147689348_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Ezbro.B"
        threat_id = "2147689348"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ezbro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Banner Clicked!" wide //weight: 1
        $x_1_2 = "webq=http://finder.strangled.net/?pubid=" wide //weight: 1
        $x_1_3 = "Searching IFrame links.." wide //weight: 1
        $x_1_4 = "Failed to hook Referer on IE8" wide //weight: 1
        $x_1_5 = "Win64_86xKernelMutex1" wide //weight: 1
        $x_1_6 = "csIWebBrowse.AScript" wide //weight: 1
        $x_1_7 = "minion=true constants={0}" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule TrojanClicker_MSIL_Ezbro_C_2147690660_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanClicker:MSIL/Ezbro.C"
        threat_id = "2147690660"
        type = "TrojanClicker"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Ezbro"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {31 65 34 63 64 00 00 0c 01 00 07 32 2e 30 2e 30 2e 30 00 00 08 01 00 02 01 00 00 00 00 08 01 00 08 00 00 00 00 00 1e 01 00 01 00 54 02 16 57 72 61}  //weight: 1, accuracy: High
        $x_1_2 = {63 68 65 72 00 44 61 74 61 00 6d 73 63 6f 72 6c 69 62 00 53 79 73 74 65 6d 00 4f 62 6a 65 63 74 00 58 6f 72 4b 65 79 00 58 6f 72 45 6e 63 72 79 70 74 4f 72 44 65}  //weight: 1, accuracy: High
        $x_1_3 = {68 00 50 61 74 68 00 47 65 74 46 75 6c 6c 50 61 74 68 00 4f 70 65 6e 52 65 61 64 00 45 78 63 65 70 74 69 6f 6e 00 2e 63 63 74 6f 72 00 45 6e 63 6f 64 69}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

