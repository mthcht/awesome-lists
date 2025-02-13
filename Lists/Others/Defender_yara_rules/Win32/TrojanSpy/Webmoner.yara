rule TrojanSpy_Win32_Webmoner_J_2147602419_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Webmoner.J"
        threat_id = "2147602419"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Webmoner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "152%7v.Q0F.30y.*17" ascii //weight: 1
        $x_1_2 = "ttttttttttttttttt dfsdfsdf uihiuattttttttttttttttttth" ascii //weight: 1
        $x_1_3 = {5c 26 73 23 79 32 73 57 74 37 65 2a 6d 6d 33 2f 32 77 5c 57 64 63 72 2a 69 23 76 51 65 32 72 35 73 77 5c 46 65 77 74 38 63 37 5c 26 68 2a 6f 35 73 23 74 37 73 26 00 00 ?? ?? ?? ?? ?? ?? ?? ?? 5c 62 73 37 76 32 63 37 68 79}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Webmoner_N_2147624101_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Webmoner.N"
        threat_id = "2147624101"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Webmoner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Software\\WebMoney" ascii //weight: 1
        $x_1_2 = "&DAY=" ascii //weight: 1
        $x_1_3 = "data//sum" ascii //weight: 1
        $x_1_4 = "?uin=" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Webmoner_P_2147626381_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Webmoner.P"
        threat_id = "2147626381"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Webmoner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "1"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {63 75 74 65 41 00 4f 20 44 41 20 4e 49 47 45 52}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule TrojanSpy_Win32_Webmoner_S_2147626681_0
{
    meta:
        author = "defender2yara"
        detection_name = "TrojanSpy:Win32/Webmoner.S"
        threat_id = "2147626681"
        type = "TrojanSpy"
        platform = "Win32: Windows 32-bit platform"
        family = "Webmoner"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "webmoney.exe" ascii //weight: 1
        $x_1_2 = "http://passport.webmoney.ru/asp/certview.asp?wmid=" ascii //weight: 1
        $x_1_3 = "Send WebMoney" ascii //weight: 1
        $x_1_4 = "dilll.dll" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

