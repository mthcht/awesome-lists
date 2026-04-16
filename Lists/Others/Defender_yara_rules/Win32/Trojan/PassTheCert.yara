rule Trojan_Win32_PassTheCert_AM_2147967141_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PassTheCert.AM"
        threat_id = "2147967141"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PassTheCert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "passthecert" wide //weight: 1
        $x_1_2 = "--cert-pfx" wide //weight: 1
        $x_1_3 = "--server" wide //weight: 1
        $x_1_4 = "--elevate" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_PassTheCert_MK_2147967142_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PassTheCert.MK"
        threat_id = "2147967142"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PassTheCert"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "passthecert" wide //weight: 1
        $x_1_2 = "cert-p" wide //weight: 1
        $x_1_3 = "server" wide //weight: 1
        $x_1_4 = "elevate" wide //weight: 1
        $x_1_5 = "rbcd" wide //weight: 1
        $x_1_6 = "add-computer" wide //weight: 1
        $x_1_7 = "reset-password" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

