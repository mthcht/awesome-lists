rule Trojan_Win32_KiraStealer_PA_2147753639_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KiraStealer.PA!MTB"
        threat_id = "2147753639"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KiraStealer"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Stealer" wide //weight: 1
        $x_1_2 = "Ethereum" wide //weight: 1
        $x_1_3 = "Monero" wide //weight: 1
        $x_1_4 = "Google\\Chrome\\User Data\\Default\\Login Data" wide //weight: 1
        $x_1_5 = "Opera Software\\Opera Stable\\Login Data" wide //weight: 1
        $x_1_6 = "Passwords.txt" wide //weight: 1
        $x_1_7 = "Cookies.txt" wide //weight: 1
        $x_1_8 = "credit_cards" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

