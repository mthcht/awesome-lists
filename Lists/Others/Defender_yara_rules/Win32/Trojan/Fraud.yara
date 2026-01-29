rule Trojan_Win32_Fraud_PGFR_2147961946_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/Fraud.PGFR!MTB"
        threat_id = "2147961946"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "Fraud"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "10"
        strings_accuracy = "Low"
    strings:
        $x_5_1 = "powershell.exe  -WindowStyle Hidden -ExecutionPolicy Bypass -File \"C:\\TEMP\\clean_policies.ps1" ascii //weight: 5
        $x_5_2 = {68 00 74 00 74 00 70 00 [0-2] 3a 00 2f 00 2f 00 [0-63] 2f 00 69 00 6e 00 73 00 74 00 61 00 6c 00 61 00 64 00 6f 00 72 00 2f 00 74 00 6f 00 6b 00 65 00 6e 00 2e 00 74 00 78 00 74 00 3f 00}  //weight: 5, accuracy: Low
        $x_5_3 = {68 74 00 74 00 70 [0-2] 3a 2f 2f [0-63] 2f 69 6e 73 74 61 6c 61 64 6f 72 2f 74 6f 6b 65 6e 2e 74 78 74 3f}  //weight: 5, accuracy: Low
    condition:
        (filesize < 20MB) and
        (2 of ($x*))
}

