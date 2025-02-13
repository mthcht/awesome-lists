rule Trojan_Win32_Claretore_A_2147653677_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Claretore.gen!A"
        threat_id = "2147653677"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Claretore"
        severity = "Critical"
        info = "gen: malware that is detected using a generic signature"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {74 1b 8b 4d 0c 8b 46 3c 3b cb 74 0d 66 8b 44 30 16 66 c1 e8 0d 24 01 88 01 c6 45 ff 01}  //weight: 1, accuracy: High
        $x_1_2 = {50 0f 31 50 68 ?? ?? ?? ?? 8d 44 24 7c 6a 40 50}  //weight: 1, accuracy: Low
        $x_1_3 = "$mid=%S&uid=%d&version=%s$" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Claretore_I_2147664391_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Claretore.I"
        threat_id = "2147664391"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Claretore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "$mid=%S&uid=%d&version=%s$" ascii //weight: 1
        $x_1_2 = "v=spf1 a mx ip4" ascii //weight: 1
        $x_1_3 = {0f 31 52 50 68 94 e3 40 00 8d 85 fc fb ff ff 68 04 01 00 00 50 ff 15}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Claretore_L_2147680043_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Claretore.L"
        threat_id = "2147680043"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Claretore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src=\"http://%s/%s?%s=%s\"><" ascii //weight: 1
        $x_1_2 = "$mid=%s&uid=%d&version=%s" ascii //weight: 1
        $x_1_3 = "wv=%s&uid=%d&lng=%s&" ascii //weight: 1
        $x_1_4 = "report%s.%s.com" ascii //weight: 1
        $x_1_5 = "v=spf1 a mx ip4:" ascii //weight: 1
        $x_2_6 = "\\[Release.Win32]Clicker.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

rule Trojan_Win32_Claretore_M_2147682498_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Claretore.M"
        threat_id = "2147682498"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Claretore"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "src=\"http://%s/%s?%s=%s\"><" ascii //weight: 1
        $x_1_2 = "$mid=%s&uid=%d&version=%s" ascii //weight: 1
        $x_1_3 = "wv=%s&uid=%d&lng=%s&" ascii //weight: 1
        $x_1_4 = "report%s.%s.com" ascii //weight: 1
        $x_1_5 = "v=spf1 a mx ip4:" ascii //weight: 1
        $x_2_6 = "\\[Release.Win32]Clicker.pdb" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (
            ((3 of ($x_1_*))) or
            ((1 of ($x_2_*) and 1 of ($x_1_*))) or
            (all of ($x*))
        )
}

