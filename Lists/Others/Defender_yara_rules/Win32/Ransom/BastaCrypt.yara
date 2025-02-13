rule Ransom_Win32_BastaCrypt_PB_2147817735_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/BastaCrypt.PB!MTB"
        threat_id = "2147817735"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "BastaCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "\\readme.txt" wide //weight: 1
        $x_1_2 = "dlaksjdoiwq.jpg" wide //weight: 1
        $x_1_3 = "Done time: %.4f seconds, encrypted: %.4f gb" ascii //weight: 1
        $x_1_4 = "All of your files are currently encrypted" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

