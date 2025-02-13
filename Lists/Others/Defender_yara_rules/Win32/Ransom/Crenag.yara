rule Ransom_Win32_Crenag_ARG_2147759912_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Crenag.ARG!MTB"
        threat_id = "2147759912"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Crenag"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = {59 83 65 fc 00 8b 35 ?? ?? ?? ?? 8b ce 83 e1 1f 33 35 ?? ?? ?? ?? d3 ce 89 75 e4 c7 45 fc}  //weight: 1, accuracy: Low
        $x_1_2 = "CryptoCymulate_Decrypted.txt" wide //weight: 1
        $x_1_3 = "CryptoCymulate_Encrypted.txt" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

