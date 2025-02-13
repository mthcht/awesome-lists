rule Trojan_Win32_KoiLoader_GQZ_2147914803_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KoiLoader.GQZ!MTB"
        threat_id = "2147914803"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KoiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b c8 83 e1 0f 8a 0c 31 30 0c 07 40 3b c2 72 f0}  //weight: 10, accuracy: High
        $x_1_2 = "\\Jaxx\\Local Storage\\wallet.dat" ascii //weight: 1
        $x_1_3 = "OpenVPN.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_KoiLoader_GX_2147915512_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/KoiLoader.GX!MTB"
        threat_id = "2147915512"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "KoiLoader"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "12"
        strings_accuracy = "High"
    strings:
        $x_10_1 = {8b ca 83 e1 0f 8a 44 0d bc 30 04 3a 42 3b d6 72}  //weight: 10, accuracy: High
        $x_1_2 = "\\Local Storage\\wallet.dat" ascii //weight: 1
        $x_1_3 = "OpenVPN.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

