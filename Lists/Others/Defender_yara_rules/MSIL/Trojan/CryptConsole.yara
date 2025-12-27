rule Trojan_MSIL_CryptConsole_AMTB_2147958271_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:MSIL/CryptConsole!AMTB"
        threat_id = "2147958271"
        type = "Trojan"
        platform = "MSIL: .NET intermediate language scripts"
        family = "CryptConsole"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "EnableLUA /t REG_DWORD /d 0" ascii //weight: 2
        $x_2_2 = "certutil -urlcache -split -f" ascii //weight: 2
        $x_2_3 = "https://realvirus.fake.com/download/scvhost" ascii //weight: 2
        $x_2_4 = "C:\\Windows\\System32\\notsvchost.exe" ascii //weight: 2
        $x_2_5 = "powershell.exe -EncodedCommand" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

