rule Trojan_Win32_Boxter_CA_2147841035_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boxter.CA!MTB"
        threat_id = "2147841035"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boxter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 6c 24 3c 0f be 5d 00 33 5c 24 30 53 8b 6c 24 40 58 88 45 00 8b 5c 24 3c 43 89 5c 24 3c ff 44 24 28 0f}  //weight: 5, accuracy: High
        $x_5_2 = "http://9ecc-23-243-99-186.ngrok.io" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_Boxter_CB_2147841037_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Boxter.CB!MTB"
        threat_id = "2147841037"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Boxter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_5_1 = {8b 6c 24 3c 0f be 5d 00 33 5c 24 30 53 8b 6c 24 40 58 88 45 00 8b 5c 24 3c 43 89 5c 24 3c ff 44 24 28 0f}  //weight: 5, accuracy: High
        $x_1_2 = "CALL mflink.bat" ascii //weight: 1
        $x_1_3 = "copy proyecto\\mflink.bat wget\\wget_32bit\\" ascii //weight: 1
        $x_1_4 = "%temp%\\getadmin.vbs" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

