rule Ransom_MSIL_Chalkrypt_A_2147726465_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/Chalkrypt.A"
        threat_id = "2147726465"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Chalkrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_4_1 = "http://chickenluck.win" wide //weight: 4
        $x_4_2 = "https://www.sazava.pw/" wide //weight: 4
        $x_4_3 = "== TEST EGG LOCKERU ==" wide //weight: 4
        $x_4_4 = "EGG\\EGG.txt" wide //weight: 4
        $x_4_5 = "Chicken has just awoken!" wide //weight: 4
        $x_4_6 = "Your pc has to pay for all files otherwise" wide //weight: 4
        $x_4_7 = "small chicken is going to eat them all!" wide //weight: 4
        $x_4_8 = "There is no way to kill chicken." wide //weight: 4
        $x_4_9 = "C:\\Users\\Krysto\\source\\repos\\WindowsFormsApp1\\WindowsFormsApp1\\obj\\Debug\\EGG.pdb" ascii //weight: 4
        $x_4_10 = "C:\\Users\\Krysto\\source\\repos\\WindowsFormsApp1\\WindowsFormsApp1\\obj\\Debug\\WindowsFormsApp1.pdb" ascii //weight: 4
        $x_1_11 = "/F /IM explorer.exe" wide //weight: 1
        $x_1_12 = "/F /IM MicrosoftEdgeCP.exe" wide //weight: 1
        $x_1_13 = "/IM taskmgr.exe" wide //weight: 1
        $x_1_14 = "/F /IM outlook.exe" wide //weight: 1
        $x_1_15 = "/F /IM avguard.exe" wide //weight: 1
        $x_1_16 = "/F /IM ashServ.exe" wide //weight: 1
        $x_1_17 = "/F /IM AVENGINE.exe" wide //weight: 1
        $x_1_18 = "/F /IM avgemc.exe" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_4_*) and 7 of ($x_1_*))) or
            ((3 of ($x_4_*) and 3 of ($x_1_*))) or
            ((4 of ($x_4_*))) or
            (all of ($x*))
        )
}

