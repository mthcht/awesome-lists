rule Ransom_Win32_DamCrypt_A_2147720246_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/DamCrypt.A!rsm"
        threat_id = "2147720246"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "DamCrypt"
        severity = "Critical"
        info = "rsm: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Delete Shadows /All /Quiet" wide //weight: 1
        $x_1_2 = ";Hello+Password >>" wide //weight: 1
        $x_1_3 = "shutdown.exe" wide //weight: 1
        $x_1_4 = "_how to*.txt" wide //weight: 1
        $x_1_5 = "*.LeChiffre" wide //weight: 1
        $x_1_6 = ".damage" wide //weight: 1
        $x_1_7 = "pswrds" wide //weight: 1
        $x_1_8 = "*.rdp" wide //weight: 1
        $x_1_9 = "account*.*" wide //weight: 1
        $x_1_10 = "tsclient" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (8 of ($x*))
}

