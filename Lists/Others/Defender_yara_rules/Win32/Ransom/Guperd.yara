rule Ransom_Win32_Guperd_2147725298_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Guperd"
        threat_id = "2147725298"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Guperd"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "8"
        strings_accuracy = "High"
    strings:
        $x_2_1 = "jmqapf3nflatei35.onion.link" ascii //weight: 2
        $x_2_2 = "19204ur2907ut982gi3hoje9sfa.exe" ascii //weight: 2
        $x_2_3 = "You have not paid the ransom." ascii //weight: 2
        $x_2_4 = "Congrats: you've paid. Click OK to decrypt your files (This will take a while so be patient)." ascii //weight: 2
        $x_2_5 = "MoneroPayAgent.exe" ascii //weight: 2
        $x_2_6 = "REG ADD \"HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /F /t REG_SZ /V \"MoneroPay\" /D" ascii //weight: 2
    condition:
        (filesize < 20MB) and
        (4 of ($x*))
}

