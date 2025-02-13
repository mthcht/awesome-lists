rule Trojan_Win32_Adylkuzz_B_2147721257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adylkuzz.B"
        threat_id = "2147721257"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adylkuzz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {73 75 70 65 72 04 00 04 00 2e 63 6f 6d 2f 38 36 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_2 = {57 45 4c 4d [0-4] 64 69 73 70 6c 61 79 [0-4] 57 69 6e 64 6f 77 73 20 45 76 65 6e 74 20 4c 6f 67 20 4d 61 6e 61 67 65 6d 65 6e 74}  //weight: 1, accuracy: Low
        $x_1_3 = {4d 69 6e 65 72 [0-4] 65 78 65 6e 61 6d 65 [0-8] 6d 73 69 65 78 65 76 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {77 75 61 75 73 65 72 2e 65 78 65 [0-4] 53 65 72 76 65 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Adylkuzz_C_2147721258_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adylkuzz.C"
        threat_id = "2147721258"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adylkuzz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = ".disgogoweb.com/86.exe" ascii //weight: 1
        $x_1_2 = {4d 69 6e 65 72 ?? 65 78 65 6e 61 6d 65 [0-8] 4c 4d 53 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_3 = "\\Fonts\\LMS.exe" ascii //weight: 1
        $x_1_4 = {73 70 70 73 72 76 2e 65 78 65 [0-4] 53 65 72 76 65 72}  //weight: 1, accuracy: Low
        $x_1_5 = {64 69 73 70 6c 61 79 [0-4] 4d 69 63 72 6f 73 6f 66 74 20 2e 4e 45 54 20 46 72 61 6d 65 77 6f 72 6b 20 4e 47 45 4e}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Adylkuzz_D_2147721500_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adylkuzz.D"
        threat_id = "2147721500"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adylkuzz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "cryptonight -o stratum+tcp://lmine.super1024.com" ascii //weight: 1
        $x_1_2 = "super1024.com/s/xmr/minerd" ascii //weight: 1
        $x_1_3 = "minecoins18.com" ascii //weight: 1
        $x_1_4 = "taskkill /f /im LMS.dat" ascii //weight: 1
        $x_1_5 = "taskkill /f /im Chrome.txt" ascii //weight: 1
        $x_1_6 = {77 69 6e 64 72 69 76 65 72 2e 65 78 65 [0-4] 53 65 72 76 65 72}  //weight: 1, accuracy: Low
        $x_1_7 = {57 48 44 4d 49 44 45 [0-4] 64 69 73 70 6c 61 79 [0-4] 57 69 6e 64 6f 77 73 20 48 61 72 64 77 61 72 65 20 44 72 69 76 65 72 20 4d 61 6e 61 67 65 6d 65 6e 74}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Adylkuzz_E_2147721504_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adylkuzz.E"
        threat_id = "2147721504"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adylkuzz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "best01011.com/86.exe" ascii //weight: 1
        $x_1_2 = "security\\WINSec.exe" ascii //weight: 1
        $x_1_3 = {4d 69 6e 65 72 ?? 65 78 65 6e 61 6d 65 [0-8] 57 49 4e 53 65 63 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 69 6e 65 72 ?? 65 78 65 6e 61 6d 65 [0-8] 43 68 72 6f 6d 65 2e 74 78 74}  //weight: 1, accuracy: Low
        $x_1_5 = {73 65 63 73 63 61 6e 2e 65 78 65 [0-4] 53 65 72 76 65 72}  //weight: 1, accuracy: Low
        $x_1_6 = {57 49 4e 53 53 [0-4] 64 69 73 70 6c 61 79 [0-4] 57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_Adylkuzz_F_2147721531_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Adylkuzz.F"
        threat_id = "2147721531"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Adylkuzz"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Windows\\security\\process.exe" ascii //weight: 1
        $x_1_2 = "ssr.la/86.exe" ascii //weight: 1
        $x_1_3 = {73 70 6f 6f 6c 73 76 2e 65 78 65 [0-4] 53 65 72 76 65 72}  //weight: 1, accuracy: Low
        $x_1_4 = {4d 69 6e 65 72 ?? 65 78 65 6e 61 6d 65 [0-8] 70 72 6f 63 65 73 73 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_5 = {57 69 6e 53 65 73 [0-4] 64 69 73 70 6c 61 79 [0-4] 57 69 6e 64 6f 77 73 20 53 65 63 75 72 69 74 79 20 53 65 72 76 69 63 65 73}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

