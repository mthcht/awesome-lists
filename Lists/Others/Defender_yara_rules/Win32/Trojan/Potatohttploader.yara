rule Trojan_Win32_Potatohttploader_B_2147757907_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Potatohttploader.B"
        threat_id = "2147757907"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Potatohttploader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "H4sIAAAAAAAEAO1Yb2wcxRV" ascii //weight: 1
        $x_1_2 = "Invoke" ascii //weight: 1
        $x_1_3 = "Password" ascii //weight: 1
        $x_1_4 = "hello.stg" ascii //weight: 1
        $x_1_5 = "Stop/" ascii //weight: 1
        $x_1_6 = "_Handler" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Potatohttploader_C_2147757908_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Potatohttploader.C"
        threat_id = "2147757908"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Potatohttploader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "JuicyPotato.pdb" ascii //weight: 1
        $x_1_2 = "COM -> send failed with error: %d" ascii //weight: 1
        $x_1_3 = "COM -> recv failed with error: %d" ascii //weight: 1
        $x_1_4 = "[+] CreateProcessAsUser OK" ascii //weight: 1
        $x_1_5 = "shutdown failed with error: %d" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Potatohttploader_D_2147758774_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Potatohttploader.D"
        threat_id = "2147758774"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Potatohttploader"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "TVqQAAMAAAAEAAAA//8AALg" ascii //weight: 1
        $x_1_2 = "HttpCore.Agent" ascii //weight: 1
        $x_1_3 = "https://www.example.com/Default" ascii //weight: 1
        $x_1_4 = "\\Program" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

