rule Ransom_MSIL_LockScreen_A_2147679754_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockScreen.A"
        threat_id = "2147679754"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "31"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {75 00 6e 00 6c 00 6f 00 63 00 6b 00 20 00 79 00 6f 00 75 00 72 00 20 00 (63 00 6f 00 6d 00 70 00 75 00 74 00 65|73 00 79 00 73 00 74 00 65)}  //weight: 10, accuracy: Low
        $x_10_2 = "You can only have 2 warnings" wide //weight: 10
        $x_10_3 = "ewall set opmode disable" wide //weight: 10
        $x_10_4 = {62 74 6e 53 75 72 76 65 79 (4c 69|5f 43 6c 69)}  //weight: 10, accuracy: Low
        $x_1_5 = ".fuckme.com" wide //weight: 1
        $x_1_6 = ".youporn.com" wide //weight: 1
        $x_1_7 = ".youporngay.com" wide //weight: 1
        $x_4_8 = "shutdown -s -t 0" wide //weight: 4
        $x_4_9 = "Unlock code:" wide //weight: 4
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_4_*) and 3 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_1_*))) or
            ((3 of ($x_10_*) and 1 of ($x_4_*))) or
            ((4 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_LockScreen_D_2147693610_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockScreen.D"
        threat_id = "2147693610"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "L:\\0x00\\[ransomware]\\" ascii //weight: 5
        $x_1_2 = "Timer1_Tick" ascii //weight: 1
        $x_1_3 = "sdclt" wide //weight: 1
        $x_1_4 = "rstrui" wide //weight: 1
        $x_1_5 = "powershell" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_MSIL_LockScreen_E_2147706594_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockScreen.E"
        threat_id = "2147706594"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {5c 00 52 00 75 00 6e 00 ?? ?? 52 00 65 00 61 00 6c 00 74 00 65 00 6b 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65 00}  //weight: 1, accuracy: Low
        $x_1_2 = "/set {bootmgr} displaybootmenu no" wide //weight: 1
        $x_1_3 = "1.1.1.1 -n 2 -w 3000 > Nul & Del" wide //weight: 1
        $x_1_4 = "\\Srv Lock\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_LockScreen_F_2147706606_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockScreen.F"
        threat_id = "2147706606"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {62 00 79 00 6c 00 20 00 7a 00 61 00 62 00 6c 00 6f 00 6b 00 6f 00 76 00 e1 00 6e 00 21 00}  //weight: 1, accuracy: High
        $x_1_2 = "platit kreditn" wide //weight: 1
        $x_1_3 = {5c 00 52 00 75 00 6e 00 ?? ?? 50 00 4f 00 4c 00 49 00 43 00 49 00 45 00}  //weight: 1, accuracy: Low
        $x_1_4 = {62 6c 6f 63 6b 5f 46 6f 72 6d 43 6c 6f 73 69 6e 67 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_MSIL_LockScreen_G_2147706774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockScreen.G"
        threat_id = "2147706774"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\svmachine.exe" wide //weight: 1
        $x_1_2 = "after HideFiles" wide //weight: 1
        $x_1_3 = "after Delete systeme.exe" wide //weight: 1
        $x_1_4 = "after copy systeme.exe" wide //weight: 1
        $x_1_5 = "Votre Demande a ete envoyer Vous aller recevoir un email avec un code de decryptage 'dans les 24 h" wide //weight: 1
        $x_1_6 = "Votre Demande n'a pas ete enoyer voulliez reesayer!" wide //weight: 1
        $x_1_7 = "os Donnes Personnels Ont ete Crypter, Pour les decrypter Acheter un ticket neosurf de 100 euro" wide //weight: 1
        $x_1_8 = "cryptlocker.Properties.Resources" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

rule Ransom_MSIL_LockScreen_H_2147713071_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:MSIL/LockScreen.H"
        threat_id = "2147713071"
        type = "Ransom"
        platform = "MSIL: .NET intermediate language scripts"
        family = "LockScreen"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "PLEASE DO NOT SHUT DOWN OR RESTART YOUR COMPUTER. Customer Service  1-844-459-8882" wide //weight: 1
        $x_1_2 = "Your Product Key is not match" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

