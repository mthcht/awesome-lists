rule Trojan_Win64_BrowserStealer_RDA_2147842954_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrowserStealer.RDA!MTB"
        threat_id = "2147842954"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrowserStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_2_1 = {83 e1 07 0f b6 4c 0d b7 32 0c 02 48 8d 45 d7 49 83 ff 10 49 0f 43 c6 88 0c 02 41 ff c0 48 ff c2 49 63 c8 4c 8b 7d ef 4c 8b 75 d7 48 3b 4b 10}  //weight: 2, accuracy: High
        $x_1_2 = "\\Mozilla\\Firefox\\Profiles" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win64_BrowserStealer_GVA_2147947384_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrowserStealer.GVA!MTB"
        threat_id = "2147947384"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrowserStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {48 d3 ea 41 8b c8 48 d3 e0 40 0f b6 cf 48 8b 7c 24 40 0a d0 41 0f b6 c2 d2 e0 41 0f b6 c9 41 d2 ea 41 0a c2 32 d0 0f b6 c2}  //weight: 3, accuracy: High
        $x_1_2 = "chrome" wide //weight: 1
        $x_1_3 = "firefox" wide //weight: 1
        $x_1_4 = "opera" wide //weight: 1
        $x_1_5 = "brave" wide //weight: 1
        $x_3_6 = "taskkill /IM " wide //weight: 3
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_3_*) and 2 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BrowserStealer_KZ_2147952236_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrowserStealer.KZ!MTB"
        threat_id = "2147952236"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrowserStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Reflective DLL Process Injection" ascii //weight: 1
        $x_1_2 = "Cookies" ascii //weight: 1
        $x_1_3 = "Passwords" ascii //weight: 1
        $x_1_4 = "Payment Methods" ascii //weight: 1
        $x_1_5 = "attempting to remove temp files" ascii //weight: 1
        $x_1_6 = "chrome_decrypt.log" ascii //weight: 1
        $x_2_7 = "chrome_inject.exe" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((6 of ($x_1_*))) or
            ((1 of ($x_2_*) and 4 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win64_BrowserStealer_PVA_2147960498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/BrowserStealer.PVA!MTB"
        threat_id = "2147960498"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "BrowserStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "9"
        strings_accuracy = "High"
    strings:
        $x_3_1 = {2b f8 49 8d 55 0f 44 89 74 24 48 48 8d 4d f4 48 89 4c 24 40 89 7c 24 38 48 89 44 24 30 44 89 74 24 28 4c 89 74 24 20 4c 8d 4d 80 44 8b c6 48 8b 4d e8 ff 15}  //weight: 3, accuracy: High
        $x_4_2 = "Local\\Project2_SingleInstance" wide //weight: 4
        $x_1_3 = "build_zip_payload: failed to append logs.txt" ascii //weight: 1
        $x_1_4 = "send_archive: failed to transmit zip payload" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

