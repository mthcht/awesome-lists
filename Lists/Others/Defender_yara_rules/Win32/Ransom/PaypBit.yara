rule Ransom_Win32_PaypBit_MAK_2147799605_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/PaypBit.MAK!MTB"
        threat_id = "2147799605"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "PaypBit"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "Well, Your Shit is Installed" ascii //weight: 1
        $x_1_2 = "Paypal.Win32.Ransom" ascii //weight: 1
        $x_1_3 = "DecryptFileA" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

