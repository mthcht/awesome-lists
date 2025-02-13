rule Ransom_Win32_LiquidCrypt_PA_2147793614_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/LiquidCrypt.PA!MTB"
        threat_id = "2147793614"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "LiquidCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "6"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "\\runs.txt" wide //weight: 1
        $x_1_2 = "Liquid.hta" wide //weight: 1
        $x_1_3 = "started net scan" wide //weight: 1
        $x_1_4 = "\\windows\\system32\\sc.exe" wide //weight: 1
        $x_1_5 = "not encrypting admin netwroks is enabled" wide //weight: 1
        $x_1_6 = {5c 63 70 70 45 6e 64 5c [0-16] 5c 63 70 70 45 6e 64 78 36 34 2e 70 64 62}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

