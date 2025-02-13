rule Ransom_Win32_FonixCrypter_PB_2147762066_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/FonixCrypter.PB!MTB"
        threat_id = "2147762066"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "FonixCrypter"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "reg add HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce" ascii //weight: 1
        $x_4_2 = "How To Decrypt Files.hta" ascii //weight: 4
        $x_4_3 = "Help.txt" ascii //weight: 4
        $x_1_4 = "schtasks /CREATE /SC ONLOGON /TN" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

