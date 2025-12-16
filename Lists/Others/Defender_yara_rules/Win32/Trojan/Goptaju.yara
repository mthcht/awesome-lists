rule Trojan_Win32_Goptaju_B_2147959419_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.B"
        threat_id = "2147959419"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke-restmethod" wide //weight: 1
        $x_1_2 = "iex" wide //weight: 1
        $x_1_3 = "-uri" wide //weight: 1
        $x_1_4 = ").replace(" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Goptaju_D_2147959420_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.D"
        threat_id = "2147959420"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "13"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iex" wide //weight: 10
        $x_1_2 = "new-object system.net.webclient" wide //weight: 1
        $x_1_3 = ".downloadstring(" wide //weight: 1
        $x_1_4 = ".ps1" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Goptaju_F_2147959421_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.F"
        threat_id = "2147959421"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "16"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iwr" wide //weight: 10
        $x_5_2 = {2d 00 4d 00 65 00 74 00 68 00 6f 00 64 00 20 00 50 00 6f 00 73 00 74 00 90 00 02 00 10 00 2d 00 62 00 6f 00 64 00 79 00}  //weight: 5, accuracy: High
        $x_1_3 = "systeminfo" wide //weight: 1
        $x_1_4 = "tasklist" wide //weight: 1
        $x_1_5 = {47 00 65 00 74 00 2d 00 57 00 6d 00 69 00 4f 00 62 00 6a 00 65 00 63 00 74 00 90 00 02 00 80 00 41 00 6e 00 74 00 69 00 56 00 69 00 72 00 75 00 73 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_10_*) and 1 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Goptaju_G_2147959422_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.G"
        threat_id = "2147959422"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {69 00 65 00 78 00 28 00 24 00 90 00 02 00 08 00 2b 00 24 00 90 00 02 00 08 00 2b 00 24 00 90 00 02 00 08 00 68 00 74 00 74 00 70 00}  //weight: 10, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Goptaju_C_2147959534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.C"
        threat_id = "2147959534"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "41"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "invoke-webrequest" wide //weight: 1
        $x_1_2 = "iwr" wide //weight: 1
        $x_10_3 = "-Uri" wide //weight: 10
        $x_10_4 = "-Method Put" wide //weight: 10
        $x_10_5 = {63 00 75 00 72 00 6c 00 2e 00 65 00 78 00 65 00 90 00 02 00 30 00 2d 00 2d 00 64 00 61 00 74 00 61 00 2d 00 62 00 69 00 6e 00 61 00 72 00 79 00}  //weight: 10, accuracy: High
        $x_10_6 = "net user /domain" wide //weight: 10
        $x_10_7 = "ipconfig /all" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((4 of ($x_10_*) and 1 of ($x_1_*))) or
            ((5 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Goptaju_E_2147959535_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Goptaju.E"
        threat_id = "2147959535"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Goptaju"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "iex" wide //weight: 10
        $x_1_2 = "new-object system.net.webclient" wide //weight: 1
        $x_1_3 = ".downloadstring(" wide //weight: 1
        $n_1_4 = "validated_work_needed" wide //weight: -1
        $n_1_5 = "chocolatey" wide //weight: -1
        $n_1_6 = "msp360" wide //weight: -1
        $n_1_7 = "hcpss" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

