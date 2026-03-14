rule Trojan_Win64_CookieStealer_AMTB_2147964801_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/CookieStealer!AMTB"
        threat_id = "2147964801"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "CookieStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Hello from cookie st34l3r!" ascii //weight: 1
        $x_1_2 = "\\cookie-stealer\\x64\\Release\\cookie-stealer.pdb" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

