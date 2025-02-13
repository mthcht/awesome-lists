rule Trojan_Win32_Stealgen_GA_2147795767_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Stealgen.GA!MTB"
        threat_id = "2147795767"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Stealgen"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "AntiVM" ascii //weight: 1
        $x_1_2 = "AntiSandBoxie" ascii //weight: 1
        $x_1_3 = "SbieDll.dll" ascii //weight: 1
        $x_1_4 = "vmware" ascii //weight: 1
        $x_1_5 = "detected" ascii //weight: 1
        $x_1_6 = "Discord" ascii //weight: 1
        $x_1_7 = "<password>" ascii //weight: 1
        $x_1_8 = "<channel" ascii //weight: 1
        $x_1_9 = "Grabber" ascii //weight: 1
        $x_1_10 = "ProcessKill" ascii //weight: 1
        $x_1_11 = "RobloxCookies" ascii //weight: 1
        $x_1_12 = "SELECT name,value,host FROM moz_cookies" ascii //weight: 1
        $x_1_13 = "name=\"payload_json\"" ascii //weight: 1
        $x_1_14 = "https://discordapp.com/api/v{0}" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (11 of ($x*))
}

