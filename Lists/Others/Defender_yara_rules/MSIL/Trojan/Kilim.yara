rule Trojan_MSIL_Kilim_A_2147687605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.A"
        threat_id = "2147687605"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Form1_Load" ascii //weight: 1
        $x_1_2 = "MyProject" ascii //weight: 1
        $x_1_3 = "\\Google\\Chrome\\User Data\\Default\\Preferences" wide //weight: 1
        $x_1_4 = "taskkill /F /IM chrome.exe" wide //weight: 1
        $x_1_5 = "/background.js" wide //weight: 1
        $x_1_6 = "/manifest.json" wide //weight: 1
        $x_1_7 = "/Preferences.exe" wide //weight: 1
        $x_2_8 = {01 00 70 28 ?? 00 00 0a 0a 7e ?? 00 00 0a 72 ?? ?? 00 70 6f ?? 00 00 0a 72 ?? ?? 00 70 72 ?? ?? 00 70 6f ?? 00 00 0a}  //weight: 2, accuracy: Low
        $x_2_9 = {70 18 16 15 28 ?? 00 00 0a 26 06 72 ?? ?? 00 70 28 ?? 00 00 0a 28 ?? 00 00 0a}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((7 of ($x_1_*))) or
            ((1 of ($x_2_*) and 5 of ($x_1_*))) or
            ((2 of ($x_2_*) and 3 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kilim_B_2147687626_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.B"
        threat_id = "2147687626"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Form1_Load" ascii //weight: 1
        $x_1_2 = "recallingsystem" ascii //weight: 1
        $x_1_3 = "background.js" wide //weight: 1
        $x_1_4 = "manifest.json" wide //weight: 1
        $x_2_5 = "\\System32\\AdobeFlashPlayer\\svchost.exe" wide //weight: 2
        $x_2_6 = {13 0e 11 0e 8e 69 16 fe 02 16 fe 01 13 11 11 11 2d 28 00 16 13 0f 2b 13 00 11 0e 11 0f 9a 6f ?? ?? 00 0a 00 00 11 0f 17 58 13 0f 11 0f 11 0e 8e 69 fe 04 13 11 11 11 2d df}  //weight: 2, accuracy: Low
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 3 of ($x_1_*))) or
            ((2 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kilim_C_2147687707_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.C"
        threat_id = "2147687707"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {06 20 e8 03 00 00 6f ?? 00 00 0a 00 02 6f ?? 00 00 06 6f ?? 00 00 0a 00 02 6f ?? 00 00 06 20 f4 01}  //weight: 1, accuracy: Low
        $x_1_2 = {52 65 53 74 61 72 74 53 65 72 76 65 72 00 54 69 6d 65 72 31 5f 54 69 63 6b}  //weight: 1, accuracy: High
        $x_1_3 = {74 00 61 00 73 00 6b 00 6b 00 69 00 6c 00 6c 00 20 00 2f 00 46 00 20 00 2f 00 49 00 4d 00 20 00 [0-16] 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_4 = {47 00 6f 00 6f 00 67 00 6c 00 65 00 5c 00 43 00 68 00 72 00 6f 00 6d 00 65 00 5c 00 55 00 73 00 65 00 72 00 20 00 44 00 61 00 74 00 61 00 5c 00 44 00 65 00 66 00 61 00 75 00 6c 00 74 00 5c 00 ?? ?? 50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 ?? ?? 45 00 78 00 74 00 65 00 6e 00 73 00 69 00 6f 00 6e 00 73 00 5c 00}  //weight: 1, accuracy: Low
        $x_1_5 = {47 00 f6 00 72 00 65 00 76 00 20 00 59 00 f6 00 6e 00 65 00 74 00 69 00 63 00 69 00 73 00 69 00 20 00 2d 00 20 00 47 00 6f 00 6f 00 67 00 6c 00 65 00 20 00 43 00 68 00 72 00 6f 00 6d 00 65 00}  //weight: 1, accuracy: High
        $x_1_6 = {5c 00 62 00 67 00 2e 00 (74 00 78 00|6a 00)}  //weight: 1, accuracy: Low
        $x_1_7 = {5c 00 41 00 50 00 50 00 [0-2] 44 00 41 00 54 00 41 00 5c 00 77 00 69 00 6e 00 75 00 70 00 64 00 61 00 74 00 65 00 72 00 2e 00 65 00 78 00 65 00}  //weight: 1, accuracy: Low
        $x_1_8 = {50 00 72 00 65 00 66 00 65 00 72 00 65 00 6e 00 63 00 65 00 73 00 2e 00 74 00 78 00 74 00 ?? ?? 62 00 67 00 2e 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (7 of ($x*))
}

rule Trojan_MSIL_Kilim_D_2147688166_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.D"
        threat_id = "2147688166"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "facebook.com/csp.php" ascii //weight: 2
        $x_2_2 = {63 68 72 6f 6d 65 2e 74 61 62 73 2e 72 65 6d 6f 76 65 28 90 02 10 2e 69 64 29 3b}  //weight: 2, accuracy: High
        $x_1_3 = "xhr.responseText" ascii //weight: 1
        $x_1_4 = "xhr.open(\"GET\"" ascii //weight: 1
        $x_1_5 = "xhr.send();" ascii //weight: 1
        $x_1_6 = "Math.random()" ascii //weight: 1
        $x_1_7 = "\"blocking\"" ascii //weight: 1
        $x_1_8 = "url.indexOf('devtools://')" ascii //weight: 1
        $x_1_9 = "chrome://extensions/" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_2_*) and 7 of ($x_1_*))) or
            ((2 of ($x_2_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_MSIL_Kilim_F_2147690043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.F"
        threat_id = "2147690043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QwA6AFwAVwBpAG4AZABvAHcAcwBcAGQAdwBtAHYAcwAuAGUAeABlAA==" wide //weight: 1
        $x_1_2 = "aAB0AHQAcAA6AC8ALwBnAG8AbwAuAGcAbAAvA" wide //weight: 1
        $x_1_3 = "Facebook_Videos_Player.Resources" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kilim_F_2147690043_1
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.F"
        threat_id = "2147690043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "QwA6AFwAVwBpAG4AZABvAHcAcwBcAGQAdwBtAHYAcwAuAGUAeABlAA==" wide //weight: 1
        $x_1_2 = "\\Dupstep\\Dupstep\\obj\\x86\\Debug\\Dupstep" ascii //weight: 1
        $x_1_3 = "\\Mainstage\\Mainstage\\obj\\x86\\Debug\\Mainstage" ascii //weight: 1
        $x_1_4 = "\\Sunny Player\\Sunny Player\\obj\\x86\\Debug\\Sunny Player" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Kilim_F_2147690043_2
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.F"
        threat_id = "2147690043"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "WQBRAEEAdQBBAEgAUQBBAGUAQQBCADAAQQBBAD0APQA=" wide //weight: 1
        $x_1_2 = "XABHAG8AbwBnAGwAZQAgAEMAaAByAG8AbQBlAC4AbABuAGsA" wide //weight: 1
        $x_1_3 = "\\up\\Function\\obj\\x86\\Debug\\Function" ascii //weight: 1
        $x_1_4 = "\\dwmsi\\dwmsi\\obj\\x86\\Debug\\dwmsi" ascii //weight: 1
        $x_1_5 = "\\up\\Antwoord\\Antwoord\\obj\\x86\\Debug\\Antwoord" ascii //weight: 1
        $x_1_6 = {57 00 51 00 42 00 52 00 41 00 45 00 49 00 41 00 4e 00 41 00 42 00 42 00 41 00 45 00 67 00 41 00 55 00 51 00 42 00 42 00 41 00 46 00 6f 00 41 00 55 00 51 00 42 00 43 00 41 00 48 00 6b 00 41 00 51 00 51 00 42 00 45 00 41 00 45 00 55 00 41 00 51 00 51 00 41 00 3d 00 ?? ?? 5c 00 42 00 6f 00 6f 00 6b 00 6d 00 61 00 72 00 6b 00 73 00}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

rule Trojan_MSIL_Kilim_G_2147692985_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.G"
        threat_id = "2147692985"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "32"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "bQBhAG4AaQBhAHkAaQByADEAMgAzADQANQA" wide //weight: 1
        $x_1_2 = "YwByAHgAawBvAGQAYQB5AGkAcgAxADIAMwA0ADUA" wide //weight: 1
        $x_10_3 = "dABhAHMAawBrAGkAbABsACAALwBGACAALwBJAE0AIABjAGgAcgBvAG0AZQAuAGUAeABlAA" wide //weight: 10
        $x_10_4 = "dABhAHMAawBrAGkAbABsACAALwBGACAALwBJAE0AIABiAHIAbwB3AHMAZQByAC4AZQB4AGUA" wide //weight: 10
        $x_10_5 = "dABhAHMAawBrAGkAbABsACAALwBGACAALwBJAE0AIABvAHAAZQByAGEALgBlAHgAZQA" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kilim_H_2147694565_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.H"
        threat_id = "2147694565"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "XABkAG8AYwAuAGMAcgB4AA==" wide //weight: 1
        $x_1_2 = "RABpAHMAYQBiAGwAZQBBAHUAdABvAFUAcABkAGEAdABlAEMAaABlAGMAawBzAEMAaABlAGMAawBiAG8AeABWAGEAbAB1AGUA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kilim_J_2147705825_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.J"
        threat_id = "2147705825"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "dABhAHMAawBrAGkAbABsACAALwBGACAALwBJAE0AIABjAGgAcgBvAG0AZQAuAGUAeABlAA" wide //weight: 1
        $x_1_2 = "aAB0AHQAcAA6AC8ALwBnAG8AbwAuAGcAbAAvA" wide //weight: 1
        $x_1_3 = "XABMAG8AYwBhAGwAIABTAGUAdAB0AGkAbgBnAHMAXABBAHAAcABsAGkAYwBhAHQAaQBvAG4AIABEAGEAdABhAFwARwBvAG8AZwBsAGUA" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kilim_K_2147705826_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.K"
        threat_id = "2147705826"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "UgB3AEIAdgBBAEcAOABBAFoAdwBCAHMAQQBHAFUAQQBJAEEAQgBWAEEASABBAEEAWgBBAEIAaABBAEgAUQBBAFoAUQBBAD0A" wide //weight: 1
        $x_1_2 = "UQB3AEEANgBBAEYAdwBBAFYAdwBCAHAAQQBHADQAQQBaAEEAQgB2AEEASABjAEEAYwB3AEIAYwBBAEcAUQ" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_MSIL_Kilim_L_2147705827_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/Kilim.L"
        threat_id = "2147705827"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "Kilim"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "aAB0AHQAcABzADoALwAvAGsAbwBtAGUAbgBlAHIALgBnAG8AbwBnAGwAZQBjAG8AZABl" wide //weight: 1
        $x_1_2 = {51 00 77 00 41 00 36 00 41 00 46 00 77 00 41 00 56 00 77 00 42 00 70 00 41 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

