rule PWS_Win32_Racealer_GKM_2147774296_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Racealer.GKM!MTB"
        threat_id = "2147774296"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "1"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {b8 f8 94 08 00 01 45 ?? 8b 45 ?? 8a 04 30 8b 0d ?? ?? ?? ?? 88 04 31 81 3d ?? ?? ?? ?? 03 02 00 00 75 ?? 53 53 ff 15 ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 46 3b 35 ?? ?? ?? ?? 72}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Racealer_GKM_2147774296_1
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Racealer.GKM!MTB"
        threat_id = "2147774296"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "17"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_2 = "\\Microsoft\\Edge\\User Data" ascii //weight: 1
        $x_1_3 = "\\Comodo\\Dragon\\User Data" ascii //weight: 1
        $x_1_4 = "\\Tencent\\QQBrowser\\User Data" ascii //weight: 1
        $x_1_5 = "Login Data" ascii //weight: 1
        $x_1_6 = "Cookies" ascii //weight: 1
        $x_1_7 = "image/jpeg" ascii //weight: 1
        $x_1_8 = "SMTP Email Address" ascii //weight: 1
        $x_1_9 = "HTTPMail User Name" ascii //weight: 1
        $x_1_10 = "HTTPMail Password2" ascii //weight: 1
        $x_1_11 = "inetcomm server passwords" ascii //weight: 1
        $x_1_12 = "outlook account manager passwords" ascii //weight: 1
        $x_1_13 = "Web Data.*" ascii //weight: 1
        $x_1_14 = "ET wALLETS|eLECTRU!L@BIHODHOGN" ascii //weight: 1
        $x_1_15 = "machineinfo.txt" ascii //weight: 1
        $x_1_16 = "screen.jpeg" ascii //weight: 1
        $x_1_17 = "wallets\\" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Racealer_GKM_2147774296_2
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Racealer.GKM!MTB"
        threat_id = "2147774296"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "18"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "image/jpeg" ascii //weight: 1
        $x_1_2 = "inetcomm server passwords" ascii //weight: 1
        $x_1_3 = "outlook account manager passwords" ascii //weight: 1
        $x_1_4 = "\\Software\\Microsoft\\Internet Account Manager\\Accounts" ascii //weight: 1
        $x_1_5 = "machineinfo.txt" ascii //weight: 1
        $x_1_6 = "screen.jpeg" ascii //weight: 1
        $x_1_7 = "Login Data" ascii //weight: 1
        $x_1_8 = "Cookies" ascii //weight: 1
        $x_1_9 = "Cookies.*" ascii //weight: 1
        $x_1_10 = "Web Data.*" ascii //weight: 1
        $x_1_11 = "wallets\\" ascii //weight: 1
        $x_1_12 = "\\Google\\Chrome\\User Data" ascii //weight: 1
        $x_1_13 = "\\Microsoft\\Edge\\User Data" ascii //weight: 1
        $x_1_14 = "\\Comodo\\Dragon\\User Data" ascii //weight: 1
        $x_1_15 = "\\BraveSoftware\\Brave-Browser\\User Data" ascii //weight: 1
        $x_1_16 = "\\Safer Technologies\\Secure Browser\\User Data" ascii //weight: 1
        $x_1_17 = "\\Tencent\\QQBrowser\\User Data" ascii //weight: 1
        $x_1_18 = {f6 d1 30 4c 15 ?? 42 83 fa 05 73 ?? 8a 4d ?? eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Racealer_KM_2147776588_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Racealer.KM!MTB"
        threat_id = "2147776588"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {33 c0 39 1d ?? ?? ?? ?? 76 ?? 8b 0d ?? ?? ?? ?? 8a 8c 01 ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 88 0c 02 8b 0d ?? ?? ?? ?? 81 f9 03 02 00 00 75 ?? 89 1d ?? ?? ?? ?? 40 3b c1 72}  //weight: 1, accuracy: Low
        $x_1_2 = {30 04 37 83 fb 19 75}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule PWS_Win32_Racealer_RTH_2147779791_0
{
    meta:
        author = "defender2yara"
        detection_name = "PWS:Win32/Racealer.RTH!MTB"
        threat_id = "2147779791"
        type = "PWS"
        platform = "Win32: Windows 32-bit platform"
        family = "Racealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "28"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Login Data" ascii //weight: 1
        $x_1_2 = "Web Data" ascii //weight: 1
        $x_1_3 = "UC Login Data.*" ascii //weight: 1
        $x_1_4 = "UnmapViewOfFile" ascii //weight: 1
        $x_1_5 = "CryptHashData" ascii //weight: 1
        $x_1_6 = "GetLocaleInfoW" ascii //weight: 1
        $x_1_7 = "HTTPMail User Name" wide //weight: 1
        $x_1_8 = "HTTP Password" wide //weight: 1
        $x_1_9 = "outlook account manager passwords" wide //weight: 1
        $x_10_10 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" wide //weight: 10
        $x_10_11 = "\\Software\\Microsoft\\Internet Account Manager\\Accounts" wide //weight: 10
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 8 of ($x_1_*))) or
            (all of ($x*))
        )
}

