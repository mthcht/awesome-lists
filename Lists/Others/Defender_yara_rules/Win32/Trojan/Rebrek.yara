rule Trojan_Win32_Rebrek_A_2147808081_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rebrek.A"
        threat_id = "2147808081"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebrek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "asktgt" wide //weight: 10
        $x_1_2 = "password" wide //weight: 1
        $x_1_3 = "user" wide //weight: 1
        $x_1_4 = "ticket" wide //weight: 1
        $x_1_5 = "domain" wide //weight: 1
        $x_1_6 = "/dc" wide //weight: 1
        $x_1_7 = "certificate" wide //weight: 1
        $x_1_8 = "credentials" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Rebrek_B_2147808082_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Rebrek.B"
        threat_id = "2147808082"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Rebrek"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "kerberoast" wide //weight: 10
        $x_1_2 = "creduser" wide //weight: 1
        $x_1_3 = "/spn" wide //weight: 1
        $x_1_4 = "simple " wide //weight: 1
        $x_1_5 = "ticket" wide //weight: 1
        $x_1_6 = "ldapfilter" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

