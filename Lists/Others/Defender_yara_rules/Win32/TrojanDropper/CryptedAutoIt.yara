rule TrojanDropper_Win32_CryptedAutoIt_SN_2147775976_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/CryptedAutoIt.SN!MTB"
        threat_id = "2147775976"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptedAutoIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 49 00 4d 00 20 00 24 00 [0-32] 20 00 3d 00 20 00 40 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 44 00 49 00 52 00 20 00 26 00 20 00 22 00 5c 00 42 00 6f 00 6f 00 74 00 4d 00 65 00 6e 00 75 00 55 00 58 00 22 00}  //weight: 1, accuracy: Low
        $x_1_2 = "SgrmBroker.exe" wide //weight: 1
        $x_1_3 = "WindowsActionDialogX" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDropper_Win32_CryptedAutoIt_SG_2147776226_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/CryptedAutoIt.SG!MTB"
        threat_id = "2147776226"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptedAutoIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "12"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {26 00 20 00 43 00 48 00 52 00 57 00 20 00 28 00 20 00 42 00 49 00 54 00 58 00 4f 00 52 00 20 00 28 00 20 00 41 00 53 00 43 00 20 00 28 00 20 00 [0-32] 20 00 29 00 20 00 2c 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 52 00 49 00 47 00 48 00 54 00 20 00 28 00}  //weight: 10, accuracy: Low
        $x_1_2 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-16] 20 00 3d 00 20 00 42 00 49 00 4e 00 41 00 52 00 59 00 54 00 4f 00 53 00 54 00 52 00 49 00 4e 00 47 00 20 00 28 00 20 00 22 00 30 00 78 00 22 00 20 00 26 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 54 00 52 00 49 00 4d 00 52 00 49 00 47 00 48 00 54 00 20 00 28 00}  //weight: 1, accuracy: Low
        $x_1_3 = {3d 00 20 00 53 00 54 00 52 00 49 00 4e 00 47 00 53 00 50 00 4c 00 49 00 54 00 20 00 28 00 20 00 [0-32] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_4 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-16] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDropper_Win32_CryptedAutoIt_GG_2147778355_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDropper:Win32/CryptedAutoIt.GG!MTB"
        threat_id = "2147778355"
        type = "TrojanDropper"
        platform = "Win32: Windows 32-bit platform"
        family = "CryptedAutoIt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_AUTOITHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {44 00 49 00 4d 00 20 00 24 00 [0-32] 20 00 3d 00 20 00 40 00 55 00 53 00 45 00 52 00 50 00 52 00 4f 00 46 00 49 00 4c 00 45 00 44 00 49 00 52 00 20 00 26 00 20 00}  //weight: 1, accuracy: Low
        $x_1_2 = {4c 00 4f 00 43 00 41 00 4c 00 20 00 24 00 [0-16] 20 00 3d 00 20 00 45 00 58 00 45 00 43 00 55 00 54 00 45 00 20 00 28 00}  //weight: 1, accuracy: Low
        $x_1_3 = "BINARYTOSTRING ( \"0x\"" wide //weight: 1
        $x_1_4 = {53 00 54 00 52 00 49 00 4e 00 47 00 53 00 50 00 4c 00 49 00 54 00 20 00 28 00 20 00 [0-32] 20 00 29 00}  //weight: 1, accuracy: Low
        $x_1_5 = "BITXOR (" wide //weight: 1
        $x_1_6 = "CHRW ( " wide //weight: 1
        $x_1_7 = "NEXT" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

