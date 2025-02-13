rule Trojan_Win32_Amynex_A_2147777774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amynex.A"
        threat_id = "2147777774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amynex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "|foreach{" wide //weight: 1
        $x_1_3 = "DownloadString" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 24 00 5f 00 2f 00 [0-16] 2e 00 6a 00 73 00 70 00 3f 00 [0-16] 2a 00 24 00 65 00 6e 00 76 00 3a 00 75 00 73 00 65 00 72 00 6e 00 61 00 6d 00 65 00 2a 00 24 00 65 00 6e 00 76 00 3a 00 63 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 6e 00 61 00 6d 00 65 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amynex_A_2147777774_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amynex.A"
        threat_id = "2147777774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amynex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = ").DownLoadString('http" wide //weight: 1
        $x_1_3 = ".jsp?" wide //weight: 1
        $x_1_4 = "''+[Environment]::OSVersion.version.Major)" wide //weight: 1
        $x_1_5 = ");bpu " wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amynex_A_2147777774_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amynex.A"
        threat_id = "2147777774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amynex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = ").DownLoadString('http" wide //weight: 1
        $x_1_3 = {2e 00 70 00 68 00 70 00 3f 00 [0-2] 2e 00}  //weight: 1, accuracy: Low
        $x_1_4 = "*'+[Environment]::OSVersion.version.Major);bpu ('http" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amynex_A_2147777774_3
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amynex.A"
        threat_id = "2147777774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amynex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "[Net.Dns]::GetHostAddresses(" wide //weight: 1
        $x_1_3 = ")[0].IPAddressToString+'" wide //weight: 1
        $x_1_4 = "='http://'+$" wide //weight: 1
        $x_1_5 = "DownloadData" wide //weight: 1
        $x_1_6 = "]::Create().ComputeHash(" wide //weight: 1
        $x_1_7 = "|foreach{" wide //weight: 1
        $x_1_8 = "{IEX(-join[char[]]$" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Amynex_A_2147777774_4
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amynex.A"
        threat_id = "2147777774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amynex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_2_1 = "powershell" wide //weight: 2
        $x_1_2 = "DownloadData" wide //weight: 1
        $x_1_3 = "DownloadString" wide //weight: 1
        $x_3_4 = {2e 00 6a 00 73 00 70 00 3f 00 [0-48] 3f 00 27 00 2b 00 28 00 40 00 28 00 24 00 65 00 6e 00 76 00 3a 00 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 45 00 2c 00 24 00 65 00 6e 00 76 00 3a 00 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 2c 00 28 00 67 00 65 00 74 00 2d 00 77 00 6d 00 69 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 29 00 2e 00 55 00 55 00 49 00 44 00 2c 00 28 00 72 00 61 00 6e 00 64 00 6f 00 6d 00 29 00 29 00 2d 00 6a 00 6f 00 69 00 6e 00 27 00 2a 00 27 00 29 00}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_3_*) and 1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Amynex_A_2147777774_5
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Amynex.A"
        threat_id = "2147777774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Amynex"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "4"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "powershell" wide //weight: 1
        $x_1_2 = "::FromBase64String(" wide //weight: 1
        $x_1_3 = {2d 00 6a 00 6f 00 69 00 6e 00 [0-4] 5b 00 63 00 68 00 61 00 72 00 5b 00 5d 00 5d 00 24 00}  //weight: 1, accuracy: Low
        $x_1_4 = {2e 00 6a 00 73 00 70 00 3f 00 [0-48] 3f 00 27 00 2b 00 28 00 40 00 28 00 24 00 65 00 6e 00 76 00 3a 00 43 00 4f 00 4d 00 50 00 55 00 54 00 45 00 52 00 4e 00 41 00 4d 00 45 00 2c 00 24 00 65 00 6e 00 76 00 3a 00 55 00 53 00 45 00 52 00 4e 00 41 00 4d 00 45 00 2c 00 28 00 67 00 65 00 74 00 2d 00 77 00 6d 00 69 00 6f 00 62 00 6a 00 65 00 63 00 74 00 20 00 57 00 69 00 6e 00 33 00 32 00 5f 00 43 00 6f 00 6d 00 70 00 75 00 74 00 65 00 72 00 53 00 79 00 73 00 74 00 65 00 6d 00 50 00 72 00 6f 00 64 00 75 00 63 00 74 00 29 00 2e 00 55 00 55 00 49 00 44 00 2c 00 28 00 72 00 61 00 6e 00 64 00 6f 00 6d 00 29 00 29 00 2d 00 6a 00 6f 00 69 00 6e 00 27 00 2a 00 27 00 29 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

