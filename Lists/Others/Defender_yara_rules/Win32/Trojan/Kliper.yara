rule Trojan_Win32_Kliper_A_2147695989_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Kliper.A"
        threat_id = "2147695989"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Kliper"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "7"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "1NoKsR7jcTTufgrvh6zyvyJmL2z73aQXQP" ascii //weight: 1
        $x_1_2 = "/info.php?key=" ascii //weight: 1
        $x_4_3 = "__NTDLL_CORE__" wide //weight: 4
        $x_1_4 = {e1 0b 5e 0f 8f a8 00 00 00}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

