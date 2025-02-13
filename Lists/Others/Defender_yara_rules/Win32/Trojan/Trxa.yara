rule Trojan_Win32_Trxa_A_2147683176_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trxa.A"
        threat_id = "2147683176"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trxa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%s\\%d_ATRAX_BOT_%d" wide //weight: 10
        $x_2_2 = ".onion" ascii //weight: 2
        $x_1_3 = "/auth.php?a=" ascii //weight: 1
        $x_1_4 = "Microsoft Svchost" wide //weight: 1
        $x_1_5 = "dlrunmem" ascii //weight: 1
        $x_1_6 = "dltorexec" ascii //weight: 1
        $x_1_7 = "dltorrunmem" ascii //weight: 1
        $x_1_8 = "installexec" ascii //weight: 1
        $x_1_9 = "installationlist" ascii //weight: 1
        $x_1_10 = "startbtc" ascii //weight: 1
        $x_1_11 = {66 83 78 fc 2e 75 28 66 83 78 fe 45 74 07 66 83 78 fe 65 75 1a 66 83 38 58 74 06 66 83 38 78 75 0e 66 83 78 02 45 74 13 66 83 78 02 65}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_1_*))) or
            ((1 of ($x_2_*))) or
            ((1 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Trxa_B_2147684736_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Trxa.B"
        threat_id = "2147684736"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Trxa"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {80 3f 23 8b c7 74 0c 8a 08 40 84 c9 74 20 80 38 23 75 f4}  //weight: 1, accuracy: High
        $x_1_2 = {00 71 3d 66 6f 72 6d 67 72 61 62 62 65 72 00}  //weight: 1, accuracy: High
        $x_1_3 = "<RepLookup v=\"3\">" ascii //weight: 1
        $x_1_4 = {00 46 6f 72 6d 47 72 61 62 62 65 72 44 6c 6c 2e 64 6c 6c 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

