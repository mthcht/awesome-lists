rule Trojan_Win64_ChromeStealer_AMTB_2147958479_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win64/ChromeStealer!AMTB"
        threat_id = "2147958479"
        type = "Trojan"
        platform = "Win64: Windows 64-bit platform"
        family = "ChromeStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "%s\\chrome_master_key.bin" ascii //weight: 1
        $x_1_2 = "taskkill /F /IM chrome.exe" ascii //weight: 1
        $x_1_3 = "%s\\chrome_passwords.txt" ascii //weight: 1
        $x_1_4 = "[%04d-%02d-%02d %02d:%02d:%02d] %s" ascii //weight: 1
        $x_1_5 = "Setting up COM hijack" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

