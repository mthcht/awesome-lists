rule Ransom_Win32_Pitroxin_A_2147726534_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/Pitroxin.A"
        threat_id = "2147726534"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "Pitroxin"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR"
        threshold = "15"
        strings_accuracy = "High"
    strings:
        $x_5_1 = "Ooops,your important files are encrypted" ascii //weight: 5
        $x_5_2 = "If you see this text,then your files are not accessible" ascii //weight: 5
        $x_5_3 = "Nobody can recover your files without our decryption service" ascii //weight: 5
        $x_5_4 = "Please Send $300 worth of Bitcoin to this address" ascii //weight: 5
        $x_5_5 = "1GZCw453MzQr8V2VAgJpRmKBYRDUJ8kzco" ascii //weight: 5
    condition:
        (filesize < 20MB) and
        (3 of ($x*))
}

