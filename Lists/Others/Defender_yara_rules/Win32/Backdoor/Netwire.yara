rule Backdoor_Win32_Netwire_PA_2147784062_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Netwire.PA!MTB"
        threat_id = "2147784062"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "25"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "SOFTWARE\\NetWire" ascii //weight: 15
        $x_1_2 = "filenames.txt" ascii //weight: 1
        $x_1_3 = "Host.exe" ascii //weight: 1
        $x_1_4 = "hostname" ascii //weight: 1
        $x_1_5 = "encrypted_key" ascii //weight: 1
        $x_1_6 = "encryptedUsername" ascii //weight: 1
        $x_1_7 = "encryptedPassword" ascii //weight: 1
        $x_1_8 = "%s\\Google\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_9 = "%s\\Chromium\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_10 = "%s\\Comodo\\Dragon\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_11 = "%s\\Yandex\\YandexBrowser\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_12 = "%s\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Login Data" ascii //weight: 1
        $x_1_13 = "%s\\360Chrome\\Chrome\\User Data\\Default\\Login Data" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 10 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Backdoor_Win32_Netwire_GG_2147795257_0
{
    meta:
        author = "defender2yara"
        detection_name = "Backdoor:Win32/Netwire.GG!MTB"
        threat_id = "2147795257"
        type = "Backdoor"
        platform = "Win32: Windows 32-bit platform"
        family = "Netwire"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "20"
        strings_accuracy = "High"
    strings:
        $x_15_1 = "SOFTWARE\\NetWire" ascii //weight: 15
        $x_1_2 = "filenames.txt" ascii //weight: 1
        $x_1_3 = "HostId" ascii //weight: 1
        $x_1_4 = "%Rand%" ascii //weight: 1
        $x_1_5 = "GET %s HTTP/1.1" ascii //weight: 1
        $x_1_6 = "Accept-Language: en-US,en" ascii //weight: 1
        $x_1_7 = "Connection: close" ascii //weight: 1
        $x_1_8 = "200 OK" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (
            ((1 of ($x_15_*) and 5 of ($x_1_*))) or
            (all of ($x*))
        )
}

