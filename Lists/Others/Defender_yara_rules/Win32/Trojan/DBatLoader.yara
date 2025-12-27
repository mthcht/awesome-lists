rule Trojan_Win32_DBatLoader_LKZ_2147933705_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DBatLoader.LKZ!MTB"
        threat_id = "2147933705"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DBatLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = {8d 04 1a 6a 0f 59 8b 45 ac 33 c9 8b 55 a8 e8 ?? ?? ?? ?? 8d 04 b6 8b 44 c7 14 03 45 b8 8b 55 ac 8b 4d a4 e8 ?? ?? ?? ?? 46 83 fe 06 0f 85}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_DBatLoader_PSC_2147953810_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/DBatLoader.PSC!MTB"
        threat_id = "2147953810"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "DBatLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "rico@mbox.4net.it" ascii //weight: 1
        $x_1_2 = "WINNT" ascii //weight: 1
        $x_1_3 = "echoalphabeta gamasexokosotezo" ascii //weight: 1
        $x_1_4 = "Notepad.exe" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

