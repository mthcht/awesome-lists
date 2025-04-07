rule Trojan_Win32_Agenttesla_PGA_2147937132_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agenttesla.PGA!MTB"
        threat_id = "2147937132"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {2d 00 45 00 31 00 46 00 42 00 41 00 30 00 45 00 2d 00 42 00 34 00 30 00 39 00 43 00 44 00 32 00 31 00 42 00 38 00 30 00 31 00 34}  //weight: 5, accuracy: High
        $x_5_2 = "0402E72656C6F6" wide //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Agenttesla_ZA_2147938092_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Agenttesla.ZA!MTB"
        threat_id = "2147938092"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Agenttesla"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "GetPrivateProfileString" ascii //weight: 1
        $x_1_2 = "get_OSFullName" ascii //weight: 1
        $x_1_3 = "remove_Key" ascii //weight: 1
        $x_1_4 = "FtpWebRequest" ascii //weight: 1
        $x_1_5 = "logins" ascii //weight: 1
        $x_1_6 = "1.85 (Hash, version 2, native byte-order)" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

