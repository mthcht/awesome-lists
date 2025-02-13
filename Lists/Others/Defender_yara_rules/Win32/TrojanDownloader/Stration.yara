rule TrojanDownloader_Win32_Stration_DJ_2147582052_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stration.DJ"
        threat_id = "2147582052"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {59 51 c1 e9 02 f3 a5 59 83 e1 03 f3 a4 33 ?? 0f b6 44 ?? ?? 30 04 ?? ?? 83 ?? ?? 7c}  //weight: 5, accuracy: Low
        $x_1_2 = "GET %s HTTP/1.1" ascii //weight: 1
        $x_1_3 = "Host: %s" ascii //weight: 1
        $x_1_4 = "Pragma: no-cache" ascii //weight: 1
        $x_5_5 = {43 6f 6e 74 65 6e 74 2d 4c 65 6e 67 74 68 3a [0-5] 48 54 54 50 [0-5] 32 30 30 [0-5] 34 30 34 00}  //weight: 5, accuracy: Low
        $x_1_6 = "/ntsrv32.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_5_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Stration_CC_2147593703_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stration.CC"
        threat_id = "2147593703"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "GET /dfrg32.exe HTTP/1.1" ascii //weight: 10
        $x_10_2 = {68 74 74 70 3a 2f 2f [0-192] 2e 63 6f 6d 2f 64 66 72 67 33 32 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_3 = {48 6f 73 74 3a 20 [0-192] 2e 63 6f 6d}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Stration_SW_2147598213_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stration.SW"
        threat_id = "2147598213"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "http://beruijindegunhadesun.com/ktmcheck.exe" ascii //weight: 1
        $x_1_2 = "GET /ktmcheck.exe HTTP/1.1" ascii //weight: 1
        $x_1_3 = "User-Agent: Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1)" ascii //weight: 1
        $x_1_4 = "Host: beruijindegunhadesun.com" ascii //weight: 1
        $x_1_5 = "Pragma: no-cache" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Stration_AS_2147606076_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stration.AS"
        threat_id = "2147606076"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "GET /btcheck.exe HTTP/1.1" ascii //weight: 1
        $x_1_2 = "GET /winch32.exe HTTP/1.1" ascii //weight: 1
        $x_10_3 = {68 74 74 70 3a 2f 2f 74 72 79 2d 61 6e 79 74 68 69 6e 67 2d 65 6c 73 65 2e 63 6f 6d 2f [0-10] 2e 65 78 65}  //weight: 10, accuracy: Low
        $x_10_4 = "Host: try-anything-else.com" ascii //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*))) or
            (all of ($x*))
        )
}

rule TrojanDownloader_Win32_Stration_K_2147609456_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stration.K"
        threat_id = "2147609456"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stration"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "Low"
    strings:
        $x_10_1 = "VC20XC00U" ascii //weight: 10
        $x_10_2 = {5b 72 1e 80 3e 4d 75 19 80 7e 01 5a 74 2a 8b 15 ?? ?? ?? 00 69 d2}  //weight: 10, accuracy: Low
        $x_10_3 = {68 74 74 70 3a 2f 2f 6c 6f 63 61 6c 68 6f 73 74 2d 32 2e 63 6f 6d 2f [0-8] 2e 65 78 65}  //weight: 10, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanDownloader_Win32_Stration_I_2147609983_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanDownloader:Win32/Stration.gen!I"
        threat_id = "2147609983"
        type = "TrojanDownloader"
        platform = "Win32: Windows 32-bit platform"
        family = "Stration"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {40 83 f8 1f 7c f5 (68|b9) d0 07 00 00 e8 0b 00 80 74 04}  //weight: 1, accuracy: Low
        $x_1_2 = "-=run=-" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

