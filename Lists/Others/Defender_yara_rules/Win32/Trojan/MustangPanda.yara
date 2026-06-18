rule Trojan_Win32_MustangPanda_RPX_2147905918_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MustangPanda.RPX!MTB"
        threat_id = "2147905918"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MustangPanda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "High"
    strings:
        $x_1_1 = {0f 43 85 70 ff ff ff 51 50 ff d6 83 7d bc 08 8d 4d a8 6a 00 0f 43 4d a8 8d 45 8c 83 7d a0 08 51 0f 43 45 8c 50 ff d6}  //weight: 1, accuracy: High
        $x_1_2 = "starmygame" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MustangPanda_RPY_2147905919_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MustangPanda.RPY!MTB"
        threat_id = "2147905919"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MustangPanda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "123.253.32.71" wide //weight: 1
        $x_1_2 = "EACore.dll" wide //weight: 1
        $x_1_3 = "WindowsUpdate.exe" wide //weight: 1
        $x_1_4 = "Apartment" wide //weight: 1
        $x_1_5 = {0f b7 04 0a 66 3b c7 72 0d 66 3b c3 77 08 83 c0 20 0f b7 f0 eb 02 8b f0 0f b7 01 66 3b c7 72 0b}  //weight: 1, accuracy: High
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MustangPanda_AMP_2147971331_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MustangPanda.AMP!MTB"
        threat_id = "2147971331"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MustangPanda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "11"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "SmartPrint" wide //weight: 1
        $x_1_2 = "BelievemeIamMustang-Panda" wide //weight: 1
        $x_1_3 = "DaDaBar" wide //weight: 1
        $x_1_4 = "info/faq/v6" wide //weight: 1
        $x_1_5 = "forms.microsoft.com" wide //weight: 1
        $x_1_6 = "Hi,Mustang_Panda" ascii //weight: 1
        $x_1_7 = "please believe me" ascii //weight: 1
        $x_1_8 = "DadaBank" ascii //weight: 1
        $x_1_9 = "BankChina" ascii //weight: 1
        $x_1_10 = "BankofChina" ascii //weight: 1
        $x_1_11 = "Bankofchinaunionpaycard" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Trojan_Win32_MustangPanda_PA_2147971841_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/MustangPanda.PA!MTB"
        threat_id = "2147971841"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "MustangPanda"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "Low"
    strings:
        $x_3_1 = {a1 00 20 01 10 03 c2 a3 00 20 01 10 30 04 29 41 3b ?? 72}  //weight: 3, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

