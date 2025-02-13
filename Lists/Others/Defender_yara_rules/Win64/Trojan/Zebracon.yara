rule Trojan_Win64_Zebracon_B_2147795938_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/Zebracon.B!dha"
        threat_id = "2147795938"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "Zebracon"
        severity = "Critical"
        info = "dha: an internal category used to refer to some threats"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Synacor. Inc." wide //weight: 1
        $x_1_2 = "Zimbra Soap" wide //weight: 1
        $x_1_3 = "DllRegisterServer" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

