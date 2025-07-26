rule Trojan_Win32_LameHug_DA_2147947530_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/LameHug.DA!MTB"
        threat_id = "2147947530"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "LameHug"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "125"
        strings_accuracy = "High"
    strings:
        $x_100_1 = "mkdir C:\\Programdata\\info" wide //weight: 100
        $x_10_2 = "wmic computersystem" wide //weight: 10
        $x_10_3 = "wmic cpu" wide //weight: 10
        $x_10_4 = "wmic memorychip" wide //weight: 10
        $x_10_5 = "wmic diskdrive" wide //weight: 10
        $x_10_6 = "wmic nic" wide //weight: 10
        $x_1_7 = "whoami /user" wide //weight: 1
        $x_1_8 = "dsquery user" wide //weight: 1
        $x_1_9 = "dsquery computer" wide //weight: 1
        $x_1_10 = "dsquery group" wide //weight: 1
        $x_1_11 = "dsquery ou" wide //weight: 1
        $x_1_12 = "dsquery site" wide //weight: 1
        $x_1_13 = "dsquery subnet" wide //weight: 1
        $x_1_14 = "dsquery server" wide //weight: 1
        $x_1_15 = "dsquery domain" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_100_*) and 2 of ($x_10_*) and 5 of ($x_1_*))) or
            ((1 of ($x_100_*) and 3 of ($x_10_*))) or
            (all of ($x*))
        )
}

