rule Trojan_Win32_CredInfoStealer_B_2147769629_0
{
    meta:
        author = "defender2yara"
        detection_name = "Trojan:Win32/CredInfoStealer.B"
        threat_id = "2147769629"
        type = "Trojan"
        platform = "Win32: Windows 32-bit platform"
        family = "CredInfoStealer"
        severity = "Critical"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "3"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "source\\repos\\webCreds\\obj\\Release\\webCreds.pdb" ascii //weight: 1
        $x_1_2 = "<GetCreds>g__GetVaultElementValue" ascii //weight: 1
        $x_1_3 = "[ERROR] Unable to enumerate vaults" wide //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

