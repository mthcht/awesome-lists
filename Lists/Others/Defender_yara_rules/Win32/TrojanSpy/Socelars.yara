rule TrojanSpy_Win32_Socelars_SB_2147742480_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Socelars.SB"
        threat_id = "2147742480"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Socelars"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {68 74 74 70 73 3a 2f 2f 62 69 74 62 75 63 6b 65 74 2e 6f 72 67 2f [0-48] 2f 64 6f 77 6e 6c 6f 61 64 73 2f 6d 61 72 67 69 6e 31 32 2e 65 78 65}  //weight: 5, accuracy: Low
        $x_5_2 = "http://freeunweb.pro/FreeUnWeb.exe" ascii //weight: 5
        $x_5_3 = "http://down.admin7a57a5a743894a0e.club/4.exe" ascii //weight: 5
        $x_5_4 = "https://snowfall.top/eusetup.exe" ascii //weight: 5
        $x_1_5 = {63 64 70 6c 61 79 65 72 61 73 73 69 73 74 76 [0-2] 2e 65 78 65}  //weight: 1, accuracy: Low
        $x_1_6 = "http://www.getip.pw" ascii //weight: 1
        $x_1_7 = "Chrome\\User Data\\Default\\Cookies" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_5_*) and 2 of ($x_1_*))) or
            ((2 of ($x_5_*))) or
            (all of ($x*))
        )
}

rule TrojanSpy_Win32_Socelars_KA_2147763105_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Socelars.KA!MTB"
        threat_id = "2147763105"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Socelars"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "26"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8b 42 04 83 e8 70 8b 4d fc 8b 51 90 8b 4a 04 8b 55 fc 89 44 0a 8c 8b 4d fc 83 e9 60 e8 ?? ?? ff ff 8b 4d fc 83 e9 58 e8}  //weight: 5, accuracy: Low
        $x_5_2 = {83 e8 70 8b 4d f0 8b 11 8b 4a 04 8b 55 f0 89 44 0a fc 6a 00 8b 4d f0 83 c1 10 e8 ?? ?? ff ff c6 45 fc 02}  //weight: 5, accuracy: Low
        $x_1_3 = "http\\shell\\open\\command" ascii //weight: 1
        $x_1_4 = "ngdatas.pw" ascii //weight: 1
        $x_3_5 = "ipcode.pw" ascii //weight: 3
        $x_3_6 = "nicekkk.pw" ascii //weight: 3
        $x_1_7 = "ShellExecuteExW" ascii //weight: 1
        $x_1_8 = "URLDownloadToFileW" ascii //weight: 1
        $x_3_9 = "channelinfo.pw/index.php/Home/Index/getExe" ascii //weight: 3
        $x_1_10 = "F:\\facebook_svn\\trunk\\database\\Release\\searzar.pdb" ascii //weight: 1
        $x_1_11 = "cmd.exe /c taskkill /f /im chrome.exe" ascii //weight: 1
        $x_1_12 = "extensions.settings.fiknnmcbhfmchidhlmmgoklkeogmbcmd" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Socelars_SBR_2147768097_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Socelars.SBR!MSR"
        threat_id = "2147768097"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Socelars"
        severity = "Critical"
        info = "MSR: Microsoft Security Response"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "wdsfw34erf93.com" ascii //weight: 1
        $x_1_2 = "Google\\Chrome\\User Data" wide //weight: 1
        $x_1_3 = "SELECT username_value, password_value FROM logins where origin_url LIKE" ascii //weight: 1
        $x_1_4 = "SELECT host_key, name, value, encrypted_value" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Socelars_PAA_2147783625_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Socelars.PAA!MTB"
        threat_id = "2147783625"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Socelars"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "all_payment_methods%7Bpayment_method_altpays%7Baccount_id%2Ccountry%2Ccredential_id" ascii //weight: 1
        $x_1_2 = "select * from logins where blacklisted_by_user=0" ascii //weight: 1
        $x_1_3 = "cmd.exe /c taskkill /f /im chrome.exe" ascii //weight: 1
        $x_1_4 = "/Home/Index/lkdinl" ascii //weight: 1
        $x_1_5 = "URLDownloadToFileW" ascii //weight: 1
        $x_1_6 = "/ngdatas.pw" ascii //weight: 1
        $x_1_7 = "mutexmutex" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Socelars_G_2147793029_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Socelars.G!MTB"
        threat_id = "2147793029"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Socelars"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "30"
        strings_accuracy = "High"
    strings:
        $x_10_1 = "mutex detected" ascii //weight: 10
        $x_10_2 = "Explore\":\"%ls\",\"Encode\":\"%ls\",\"cUserId\":\"%ls\",\"LoginName\":\"%ls\",\"Psw\":" ascii //weight: 10
        $x_1_3 = "www.facebook.com/payments/settings/payment_methods/" ascii //weight: 1
        $x_1_4 = "secure.facebook.com/ads/manager/account_settings/account_billing/" ascii //weight: 1
        $x_1_5 = "from logins where blacklisted_by_user=0 and preferred=1 and  origin_url like" ascii //weight: 1
        $x_1_6 = "select host_key,name,encrypted_value,expires_utc from cookies where  host_key like" ascii //weight: 1
        $x_1_7 = "\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_8 = "\"Cookie\":" ascii //weight: 1
        $x_1_9 = "\"LoginName\":" ascii //weight: 1
        $x_1_10 = "\"Balance\":" ascii //weight: 1
        $x_1_11 = "\"Psw\":" ascii //weight: 1
        $x_1_12 = "\"Paypal\":" ascii //weight: 1
        $x_1_13 = "\"CreditCard\":" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((2 of ($x_10_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

