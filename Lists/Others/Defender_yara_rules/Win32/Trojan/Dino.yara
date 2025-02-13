rule Trojan_Win32_Dino_A_2147697802_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Dino.A!dha"
        threat_id = "2147697802"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Dino"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f be db c1 c6 07 83 c2 01 33 f3 8a 1a 84 db}  //weight: 1, accuracy: High
        $x_1_2 = "%s ie %d days %d hours remain before uninstall" wide //weight: 1
        $x_1_3 = "Login/Domain (owner): %s/%s (%s)" wide //weight: 1
        $x_1_4 = "ServiceMain" ascii //weight: 1
        $x_1_5 = "PsmIsANiceM0du1eWith0SugarInside" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

