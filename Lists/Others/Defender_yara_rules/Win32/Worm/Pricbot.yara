rule Worm_Win32_Pricbot_A_2147631760_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pricbot.A"
        threat_id = "2147631760"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pricbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "22"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = {6a 07 8d 8d c8 fd ff ff 51 8d 8d ec fd ff ff e8 ?? ?? ff ff c6 45 fc 23}  //weight: 10, accuracy: Low
        $x_10_2 = "[autorun]" ascii //weight: 10
        $x_1_3 = "Passport.Net\\*" ascii //weight: 1
        $x_1_4 = "DisableNotify" ascii //weight: 1
        $x_1_5 = "Flood started" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Worm_Win32_Pricbot_C_2147642164_0
{
    meta:
        author = "defender2yara"
        detection_name = "Worm:Win32/Pricbot.C"
        threat_id = "2147642164"
        type = "Worm"
        platform = "Win32: Windows 32-bit platform"
        family = "Pricbot"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {63 6f 70 79 74 6f 00 73 70 72 65 61 64 55 53 42 00}  //weight: 10, accuracy: High
        $x_2_2 = "pircbot" ascii //weight: 2
        $x_2_3 = ".::[l4zy v1.3]::." ascii //weight: 2
        $x_1_4 = "http://h1.ripway.com/sxmast/config.php" ascii //weight: 1
        $x_1_5 = "http://sxmast.free0host.com/config.php" ascii //weight: 1
        $x_2_6 = "[SYSINF0]: [CPU]: %I64uMHz. [OS]: Windows %s (%d.%d, Build %d). [Current User]: %s." ascii //weight: 2
        $x_2_7 = "[-] Bot failed to update (initial rename failed)" ascii //weight: 2
        $x_2_8 = "[+] Password dump completed" ascii //weight: 2
        $x_2_9 = "[-] Failed to decrypt a password" ascii //weight: 2
        $x_2_10 = "[-] Unable to decrypt MSN" ascii //weight: 2
        $x_2_11 = "Passport.Net\\*" ascii //weight: 2
        $x_1_12 = "[autorun]" ascii //weight: 1
        $x_2_13 = "Flood started" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_2_*) and 2 of ($x_1_*))) or
            ((8 of ($x_2_*))) or
            ((1 of ($x_10_*) and 2 of ($x_2_*) and 2 of ($x_1_*))) or
            ((1 of ($x_10_*) and 3 of ($x_2_*))) or
            (all of ($x*))
        )
}

