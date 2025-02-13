rule Ransom_Win32_QilinCrypt_PA_2147831637_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/QilinCrypt.PA!MTB"
        threat_id = "2147831637"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "QilinCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "4"
        strings_accuracy = "High"
    strings:
        $x_1_1 = "vssadmin.exe delete shadows /all /quiet" ascii //weight: 1
        $x_1_2 = "-- Qilin" ascii //weight: 1
        $x_1_3 = "Your network/system was encrypted" ascii //weight: 1
        $x_1_4 = "README-RECOVER-.txt" ascii //weight: 1
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

rule Ransom_Win32_QilinCrypt_PD_2147915672_0
{
    meta:
        author = "defender2yara"
        detection_name = "Ransom:Win32/QilinCrypt.PD!MTB"
        threat_id = "2147915672"
        type = "Ransom"
        platform = "Win32: Windows 32-bit platform"
        family = "QilinCrypt"
        severity = "Critical"
        info = "MTB: Microsoft Threat Behavior"
        signature_type = "SIGNATURE_TYPE_PEHSTR_EXT"
        threshold = "2"
        strings_accuracy = "Low"
    strings:
        $x_1_1 = "Local\\RustBacktraceMutex" ascii //weight: 1
        $x_1_2 = {85 c0 75 12 e8 [0-4] 85 c0 0f 84 [0-4] a3 [0-4] 68 [0-4] 6a 00 50 e8 [0-4] 85 c0 0f 84 [0-4] 31 d2 bf [0-4] bb [0-4] 89 45 [0-4] c7 45 [0-4] 00 c7 45 [0-4] 00 eb}  //weight: 1, accuracy: Low
    condition:
        (filesize < 20MB) and
        (all of ($x*))
}

