rule Trojan_Win32_RemoteSysDisc_W_2147768643_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteSysDisc.W"
        threat_id = "2147768643"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteSysDisc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 6c 00 74 00 65 00 73 00 74 00 [0-16] 2f 00 64 00 73 00 67 00 65 00 74 00 64 00 63 00}  //weight: 1, accuracy: Low
        $n_50_2 = {2f 00 64 00 73 00 67 00 65 00 74 00 64 00 63 00 3a 00 [0-6] 2f 00 67 00 74 00 69 00 6d 00 65 00 73 00 65 00 72 00 76 00}  //weight: -50, accuracy: Low
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_RemoteSysDisc_A_2147768656_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteSysDisc.A"
        threat_id = "2147768656"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteSysDisc"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "powershell.exe" wide //weight: 1
        $x_2_2 = "get-adcomputer" wide //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_RemoteSysDisc_D_2147769385_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteSysDisc.D!net"
        threat_id = "2147769385"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteSysDisc"
        severity = "Critical"
        info = "net: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {6e 00 65 00 74 00 20 00 [0-16] 76 00 69 00 65 00 77 00}  //weight: 1, accuracy: Low
        $x_1_2 = {6e 00 65 00 74 00 2e 00 65 00 78 00 65 00 [0-16] 76 00 69 00 65 00 77 00}  //weight: 1, accuracy: Low
        $x_1_3 = {6e 00 65 00 74 00 31 00 20 00 [0-16] 76 00 69 00 65 00 77 00}  //weight: 1, accuracy: Low
        $x_1_4 = {6e 00 65 00 74 00 31 00 2e 00 65 00 78 00 65 00 [0-16] 76 00 69 00 65 00 77 00}  //weight: 1, accuracy: Low
        $n_10_5 = "\\\\localhost " wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_RemoteSysDisc_B_2147769389_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteSysDisc.B!nltest"
        threat_id = "2147769389"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteSysDisc"
        severity = "Critical"
        info = "nltest: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {6e 00 6c 00 74 00 65 00 73 00 74 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = "nltest " wide //weight: 1
        $n_1_3 = " /dc" wide //weight: -1
        $n_1_4 = "/dsgetdc" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_RemoteSysDisc_E_2147769391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteSysDisc.E!adfind"
        threat_id = "2147769391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteSysDisc"
        severity = "Critical"
        info = "adfind: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {61 00 64 00 66 00 69 00 6e 00 64 00 2e 00 65 00 78 00 65 00 00 00}  //weight: 1, accuracy: High
        $x_1_2 = " adfind" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (1 of ($x*))
}

rule Trojan_Win32_RemoteSysDisc_F_2147769392_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteSysDisc.F!ping"
        threat_id = "2147769392"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteSysDisc"
        severity = "Critical"
        info = "ping: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = " ping " wide //weight: 1
        $x_1_2 = " ping.exe" wide //weight: 1
        $x_1_3 = "\\ping.exe" wide //weight: 1
        $x_1_4 = "\\ping " wide //weight: 1
        $n_10_5 = "localhost" wide //weight: -10
        $n_10_6 = "127.0.0.1" wide //weight: -10
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (1 of ($x*))
}

rule Trojan_Win32_RemoteSysDisc_D_2147770146_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/RemoteSysDisc.D!nslookup"
        threat_id = "2147770146"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "RemoteSysDisc"
        severity = "Critical"
        info = "nslookup: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "nslookup" wide //weight: 1
        $n_1_2 = "myip.opendns.com" wide //weight: -1
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

