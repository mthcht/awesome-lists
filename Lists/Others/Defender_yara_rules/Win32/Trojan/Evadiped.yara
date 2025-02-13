rule Trojan_Win32_Evadiped_A_2147639346_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Evadiped.A"
        threat_id = "2147639346"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Evadiped"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {99 f7 f9 8b 44 24 1c 83 c6 01 8a 14 02 8a 44 3e ff 8a da f6 d3 22 d8 f6 d0 22 c2 0a d8 3b f5 88 5c 3e ff 7c d9}  //weight: 10, accuracy: High
        $x_1_2 = "A0E1054B-" ascii //weight: 1
        $x_1_3 = {23 32 30 36 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Evadiped_B_2147650215_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Evadiped.B"
        threat_id = "2147650215"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Evadiped"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "%s/%s/%d/%u/?id=%u" ascii //weight: 10
        $x_10_2 = "/webclient.php" ascii //weight: 10
        $x_10_3 = "Global\\phz.rq_" wide //weight: 10
        $x_1_4 = "u.clickscompile.com" ascii //weight: 1
        $x_1_5 = "u.uatoolbar.com" ascii //weight: 1
        $x_1_6 = "k.komplexad.com" ascii //weight: 1
        $x_1_7 = "85.17.209.3" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_10_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

