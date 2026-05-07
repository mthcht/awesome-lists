rule Trojan_Win32_PsDownExec_Z_2147968715_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownExec.Z!MTB"
        threat_id = "2147968715"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Net.WebClient;$" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".DownloadFile(" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00}  //weight: 1, accuracy: Low
        $x_1_5 = "&&del %TEMP%" wide //weight: 1
        $n_100_6 = "http://127.0.0.1" wide //weight: -100
        $n_100_7 = "http://10." wide //weight: -100
        $n_100_8 = "http://172." wide //weight: -100
        $n_100_9 = "http://192." wide //weight: -100
        $n_100_10 = "http://255." wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownExec_ZA_2147968716_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownExec.ZA!MTB"
        threat_id = "2147968716"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Net.WebClient;$" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".DownloadFile(" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00}  //weight: 1, accuracy: Low
        $x_1_5 = "&&del %TEMP%" wide //weight: 1
        $x_1_6 = ".exe http://" wide //weight: 1
        $n_100_7 = "http://127.0.0.1" wide //weight: -100
        $n_100_8 = "http://10." wide //weight: -100
        $n_100_9 = "http://172." wide //weight: -100
        $n_100_10 = "http://192." wide //weight: -100
        $n_100_11 = "http://255." wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownExec_ZB_2147968717_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownExec.ZB!MTB"
        threat_id = "2147968717"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Net.WebClient;$" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".DownloadFile(" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00}  //weight: 1, accuracy: Low
        $x_1_5 = {2e 00 64 00 6c 00 6c 00 20 00 25 00 74 00 65 00 6d 00 70 00 25 00 90 00 02 00 20 00 2e 00 74 00 6d 00 70 00 90 00 00 00}  //weight: 1, accuracy: High
        $x_1_6 = "&&del %TEMP%" wide //weight: 1
        $n_100_7 = "http://127.0.0.1" wide //weight: -100
        $n_100_8 = "http://10." wide //weight: -100
        $n_100_9 = "http://172." wide //weight: -100
        $n_100_10 = "http://192." wide //weight: -100
        $n_100_11 = "http://255." wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

rule Trojan_Win32_PsDownExec_ZD_2147968718_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/PsDownExec.ZD!MTB"
        threat_id = "2147968718"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "PsDownExec"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_CMDHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Net.WebClient;$" wide //weight: 1
        $x_1_2 = {70 00 6f 00 77 00 65 00 72 00 73 00 68 00 65 00 6c 00 6c 00 [0-80] 24 00}  //weight: 1, accuracy: Low
        $x_1_3 = ".DownloadFile(" wide //weight: 1
        $x_1_4 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 [0-6] 2e 00 [0-6] 2e 00 [0-6] 2e 00}  //weight: 1, accuracy: Low
        $x_1_5 = "&&start rundll32.exe $" wide //weight: 1
        $n_100_6 = "http://127.0.0.1" wide //weight: -100
        $n_100_7 = "http://10." wide //weight: -100
        $n_100_8 = "http://172." wide //weight: -100
        $n_100_9 = "http://192." wide //weight: -100
        $n_100_10 = "http://255." wide //weight: -100
    condition:
        (filesize < 20MB) and
        (not (any of ($n*))) and
        (all of ($x*))
}

