rule Ransom_Win32_Revencrypt_A_2147720434_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revencrypt.A"
        threat_id = "2147720434"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revencrypt"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "id=F8AE6A458DD01C9BDX&count=" ascii //weight: 2
        $x_1_2 = "%s%08X%08X%08X%08X.%s" ascii //weight: 1
        $x_1_3 = ":\\USERDATA\\*.*" ascii //weight: 1
        $x_1_4 = "# !!!HELP_FILE!!! #" ascii //weight: 1
        $x_1_5 = "ACH.ADB.ADS.AIT.AL.APJ." ascii //weight: 1
        $x_1_6 = "/js/other_scripts/get.php" ascii //weight: 1
        $x_2_7 = "%s\\Microsofts\\Windows NT\\%s.exe" ascii //weight: 2
        $x_1_8 = "MS Common User Interface" ascii //weight: 1
        $x_1_9 = "%08X%08X_Windows_Defender" ascii //weight: 1
        $x_1_10 = "%08X%08XDX" ascii //weight: 1
        $x_2_11 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQrO3EuFElsq2cyX+mgWJ4lnK5" ascii //weight: 2
        $x_1_12 = "Virus and spyware definitions couldn't be updated." ascii //weight: 1
        $x_1_13 = "===ENGLISH===" ascii //weight: 1
        $x_1_14 = "%s\\%s.TXT" ascii //weight: 1
        $x_1_15 = "agntsvc.exeisqlplussvc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            ((3 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Ransom_Win32_Revencrypt_A_2147720435_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Revencrypt.A!!Revencrypt.gen!A"
        threat_id = "2147720435"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Revencrypt"
        severity = "Critical"
        info = "Revencrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "A: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s%08X%08X%08X%08X.%s" ascii //weight: 1
        $x_1_2 = ":\\USERDATA\\*.*" ascii //weight: 1
        $x_1_3 = "# !!!HELP_FILE!!! #" ascii //weight: 1
        $x_1_4 = "ACH.ADB.ADS.AIT.AL.APJ." ascii //weight: 1
        $x_1_5 = "/js/other_scripts/get.php" ascii //weight: 1
        $x_2_6 = "%s\\Microsofts\\Windows NT\\%s.exe" ascii //weight: 2
        $x_1_7 = "MS Common User Interface" ascii //weight: 1
        $x_1_8 = "%08X%08X_Windows_Defender" ascii //weight: 1
        $x_1_9 = "%08X%08XDX" ascii //weight: 1
        $x_2_10 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCQrO3EuFElsq2cyX+mgWJ4lnK5" ascii //weight: 2
        $x_1_11 = "Virus and spyware definitions couldn't be updated." ascii //weight: 1
        $x_1_12 = "===ENGLISH===" ascii //weight: 1
        $x_1_13 = "%s\\%s.TXT" ascii //weight: 1
        $x_1_14 = "agntsvc.exeisqlplussvc.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((10 of ($x_1_*))) or
            ((1 of ($x_2_*) and 8 of ($x_1_*))) or
            ((2 of ($x_2_*) and 6 of ($x_1_*))) or
            (all of ($x*))
        )
}

