rule Trojan_Win32_HtaCrypt_A_2147761723_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HtaCrypt.A!!HtaCrypt.gen!MTB"
        threat_id = "2147761723"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HtaCrypt"
        severity = "Critical"
        info = "HtaCrypt: an internal category used to refer to some threats"
        info = "gen: malware that is detected using a generic signature"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_ARHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR COMPANY NETWORK HAS BEEN HACKED" ascii //weight: 1
        $x_1_2 = "All your important files have been encrypted!" ascii //weight: 1
        $x_1_3 = "We also gathered highly confidential/personal data" ascii //weight: 1
        $x_1_4 = "Files are also encrypted and stored securely" ascii //weight: 1
        $x_1_5 = "All data on your computers will remain encrypted forever" ascii //weight: 1
        $x_1_6 = "Your files are safe! Only modified" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

rule Trojan_Win32_HtaCrypt_D_2147763970_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/HtaCrypt.D!MTB"
        threat_id = "2147763970"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "HtaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "YOUR COMPANY NETWORK HAS BEEN HACKED" ascii //weight: 1
        $x_1_2 = "All your important files have been encrypted!" ascii //weight: 1
        $x_1_3 = "We also gathered highly confidential/personal data" ascii //weight: 1
        $x_1_4 = "Files are also encrypted and stored securely" ascii //weight: 1
        $x_1_5 = "All data on your computers will remain encrypted forever" ascii //weight: 1
        $x_1_6 = "Your files are safe! Only modified" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

