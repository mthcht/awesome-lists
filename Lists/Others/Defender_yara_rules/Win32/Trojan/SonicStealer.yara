rule Trojan_Win32_SonicStealer_STA_2147977433_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/SonicStealer.STA"
        threat_id = "2147977433"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "SonicStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "5"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "cards.json" ascii //weight: 1
        $x_1_2 = "tokens.json" ascii //weight: 1
        $x_1_3 = "passwords_account.json" ascii //weight: 1
        $x_1_4 = "DecryptData failed: 0x" ascii //weight: 1
        $x_1_5 = "Extracting comprehensive fingerprint..." ascii //weight: 1
        $x_1_6 = "NO_ABE:Browser uses legacy DPAPI encryption" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (5 of ($x*))
}

