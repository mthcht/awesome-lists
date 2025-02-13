rule Ransom_Win32_SlamCryptor_PAA_2147786536_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/SlamCryptor.PAA!MTB"
        threat_id = "2147786536"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "SlamCryptor"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "taskkill /F /IM LogonUI.exe" ascii //weight: 1
        $x_1_2 = "DisableTaskMgr" ascii //weight: 1
        $x_1_3 = "slamransomware" ascii //weight: 1
        $x_1_4 = "slam/key.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

