rule Trojan_Win32_Nottap_A_2147787448_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nottap.A"
        threat_id = "2147787448"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nottap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\pipe\\lsarpc" ascii //weight: 1
        $x_1_2 = "c681d488-d850-11d0-8c52-00c04fd90f7e" ascii //weight: 1
        $x_1_3 = "/certsrv/certfnsh.asp" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Nottap_B_2147787449_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Nottap.B"
        threat_id = "2147787449"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Nottap"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "--adcs <cs server>" ascii //weight: 1
        $x_1_2 = "/certsrv/certfnsh.asp" ascii //weight: 1
        $x_1_3 = "&CertAttrib=CertificateTemplate:" ascii //weight: 1
        $x_1_4 = "Relaying NTLMSSP_CHALLENGE to client" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

